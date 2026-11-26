use crate::{
    environment::Cancellation,
    package::{Manifest, Package},
    state::{MEMORY, State},
    trade::{TradePlugin, TradePluginPre},
    types::*,
    verification::VerificationPluginPre,
};
use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use wasmtime::{
    Config, Engine, PoolingAllocationConfig, Store, Strategy, Trap, UpdateDeadline,
    WasmFeatures as F,
    component::{
        Component, HasSelf, Linker,
        types::{ComponentExtern, ComponentItem},
    },
};
// UG-3 four-package calibration, including the pre-dispatch create boundary.
const MEASURED_MAX_STEP_FUEL: u64 = 24_154_643;
const FUEL_SAFETY_FACTOR: u64 = 2;
const FUEL_ROUNDING: u64 = 10_000_000;
const DEFAULT_FUEL: u64 =
    (MEASURED_MAX_STEP_FUEL * FUEL_SAFETY_FACTOR).div_ceil(FUEL_ROUNDING) * FUEL_ROUNDING;

#[derive(Clone)]
pub struct Options {
    pub plugin_type: String,
    pub test_only_allow_http: bool,
    /// Allow HTTP field substitution in offline replay or on a development loopback transport.
    pub test_only_allow_http_secret_fields: bool,
    pub test_only_allow_uncommitted: bool,
    /// Provisional two-package budget. Recalibrate with all four packages before freezing.
    pub fuel_per_step: u64,
    pub pool_slots: u32,
    pub max_concurrent_steps: usize,
    pub step_wall_clock: Duration,
    pub request_timeout: Duration,
}
impl Options {
    pub fn production(role: &str) -> Self {
        Self {
            plugin_type: role.into(),
            test_only_allow_http: false,
            test_only_allow_http_secret_fields: false,
            test_only_allow_uncommitted: false,
            fuel_per_step: DEFAULT_FUEL,
            pool_slots: 32,
            max_concurrent_steps: thread::available_parallelism()
                .map_or(1, usize::from)
                .min(32),
            step_wall_clock: Duration::from_millis(200),
            request_timeout: Duration::from_secs(10),
        }
    }
    pub fn replay(role: &str) -> Self {
        Self {
            step_wall_clock: Duration::from_secs(5),
            test_only_allow_http: true,
            test_only_allow_http_secret_fields: true,
            test_only_allow_uncommitted: true,
            ..Self::production(role)
        }
    }
}
/// One permit covers instantiation, execution and validation. HTTP never holds one.
pub(crate) struct Admission {
    free: Mutex<usize>,
    ready: Condvar,
}
impl Admission {
    fn new(limit: usize) -> Self {
        Self {
            free: Mutex::new(limit),
            ready: Condvar::new(),
        }
    }
    pub(crate) fn acquire(&self, cancel: &Cancellation) -> Result<StepPermit<'_>, &'static str> {
        let mut free = self.free.lock().unwrap();
        loop {
            if cancel.cancelled() {
                return Err("cancelled");
            }
            if *free > 0 {
                *free -= 1;
                return Ok(StepPermit(self));
            }
            // A cancellation flag can be shared across hosts. Wake periodically to
            // observe it, or sooner when a permit or the caller's deadline arrives.
            let poll = Duration::from_millis(5);
            let wait = cancel.deadline.map_or(poll, |d| {
                d.saturating_duration_since(Instant::now()).min(poll)
            });
            (free, _) = self.ready.wait_timeout(free, wait).unwrap();
        }
    }
}
pub(crate) struct StepPermit<'a>(&'a Admission);
impl Drop for StepPermit<'_> {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap() += 1;
        self.0.ready.notify_one()
    }
}
pub struct Host {
    pub(crate) options: Options,
    pub(crate) engine: Engine,
    pub(crate) admission: Admission,
    reference: Component,
    cache: Mutex<HashMap<String, Arc<Loaded>>>,
    _ticker: mpsc::Sender<()>,
}
enum Pre {
    Trade(TradePluginPre<State>),
    Verify(VerificationPluginPre<State>),
}
pub struct Loaded {
    pub(crate) manifest: Arc<Manifest>,
    pub digest: String,
    pre: Pre,
}
impl Loaded {
    pub(crate) fn belongs_to(&self, h: &Host) -> bool {
        Engine::same(
            &h.engine,
            match &self.pre {
                Pre::Trade(p) => p.engine(),
                Pre::Verify(p) => p.engine(),
            },
        )
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
}
fn same_interface(engine: &Engine, a: ComponentExtern, b: ComponentExtern) -> bool {
    if a.implements != b.implements || a.external_id != b.external_id {
        return false;
    }
    match (a.ty, b.ty) {
        (ComponentItem::ComponentInstance(a), ComponentItem::ComponentInstance(b)) => {
            a.exports(engine).len() == b.exports(engine).len()
                && a.exports(engine).all(|(n, t)| {
                    b.get_export(engine, n)
                        .is_some_and(|u| same_interface(engine, t, u))
                })
        }
        (ComponentItem::ComponentFunc(a), ComponentItem::ComponentFunc(b)) => {
            a.async_() == b.async_() && a.params().eq(b.params()) && a.results().eq(b.results())
        }
        (ComponentItem::Type(a), ComponentItem::Type(b)) => a == b,
        _ => false,
    }
}
impl Host {
    pub fn new(mut options: Options) -> Result<Self> {
        ensure!(
            matches!(options.plugin_type.as_str(), "payment" | "verification")
                && (1..=1024).contains(&options.pool_slots)
                && options.max_concurrent_steps > 0
                && !options.step_wall_clock.is_zero()
                && Instant::now()
                    .checked_add(options.step_wall_clock)
                    .is_some()
                && options.request_timeout <= Duration::from_secs(30),
            "invalid host options"
        );
        if options.request_timeout.is_zero() {
            options.request_timeout = Duration::from_secs(10)
        }
        let n = options.pool_slots;
        options.max_concurrent_steps = options.max_concurrent_steps.min(n as usize);
        let concurrent = options.max_concurrent_steps as u32;
        let mut pool = PoolingAllocationConfig::default();
        pool.total_component_instances(n)
            .total_core_instances(concurrent * 16)
            .total_memories(concurrent * 8)
            .total_tables(concurrent * 8)
            .max_core_instances_per_component(16)
            .max_memories_per_component(8)
            .max_tables_per_component(8)
            .max_memory_size(MEMORY)
            .table_elements(8192);
        // Whitelist bare Rust core features and synchronous components. Reserve 32 MiB
        // of virtual address space per memory slot plus a guard page. Actual memory
        // across all core instances in a step is separately capped by State.
        let mut cfg = Config::new();
        let allowed = (F::WASM2 - F::SIMD - F::GC_TYPES)
            | F::COMPONENT_MODEL
            | F::BULK_MEMORY_OPT
            | F::CALL_INDIRECT_OVERLONG;
        cfg.wasm_features(F::all() - allowed, false)
            .wasm_features(allowed, true)
            .strategy(Strategy::Cranelift)
            .consume_fuel(true)
            .epoch_interruption(true)
            .cranelift_nan_canonicalization(true)
            .memory_reservation(MEMORY as u64)
            .memory_guard_size(65536)
            .allocation_strategy(pool);
        let engine = Engine::new(&cfg)?;
        let reference = Component::new(
            &engine,
            if options.plugin_type == "payment" {
                &include_bytes!(concat!(env!("OUT_DIR"), "/trade-plugin.wasm"))[..]
            } else {
                &include_bytes!(concat!(env!("OUT_DIR"), "/verification-plugin.wasm"))[..]
            },
        )?;
        let (tx, rx) = mpsc::channel();
        let ticker = engine.clone();
        thread::Builder::new()
            .name("upstream-epoch".into())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    rx.recv_timeout(Duration::from_millis(5))
                {
                    ticker.increment_epoch()
                }
            })?;
        Ok(Self {
            admission: Admission::new(options.max_concurrent_steps),
            options,
            engine,
            reference,
            cache: Mutex::default(),
            _ticker: tx,
        })
    }
    pub fn load(&self, p: &Package) -> Result<Arc<Loaded>> {
        let m = &p.manifest;
        m.validate()?;
        ensure!(
            crate::json::canonical(&serde_json::to_value(m)?).len() <= 65536,
            "canonical manifest size limit"
        );
        ensure!(
            m.r#type == self.options.plugin_type
                && (self.options.test_only_allow_uncommitted
                    || m.build.source_commit != "uncommitted"),
            "plugin role/provenance denied"
        );
        ensure!(
            !p.wasm.is_empty() && p.wasm.len() <= 4 << 20,
            "component size limit"
        );
        let digest = p.hash();
        let mut cache = self.cache.lock().unwrap();
        if let Some(v) = cache.get(&digest) {
            return Ok(v.clone());
        }
        let c = Component::new(&self.engine, &p.wasm)?;
        let a = self.reference.component_type();
        let b = c.component_type();
        let e = &self.engine;
        ensure!(
            a.imports(e).len() == b.imports(e).len()
                && a.exports(e).len() == b.exports(e).len()
                && a.imports(e)
                    .all(|(n, t)| b.get_import(e, n).is_some_and(|u| same_interface(e, t, u)))
                && a.exports(e)
                    .all(|(n, t)| b.get_export(e, n).is_some_and(|u| same_interface(e, t, u))),
            "component does not match declared WIT world"
        );
        let mut linker = Linker::new(e);
        TradePlugin::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s)?;
        let pre = linker.instantiate_pre(&c)?;
        let pre = if m.r#type == "payment" {
            Pre::Trade(TradePluginPre::new(pre)?)
        } else {
            Pre::Verify(VerificationPluginPre::new(pre)?)
        };
        let v = Arc::new(Loaded {
            manifest: Arc::new(m.clone()),
            digest: digest.clone(),
            pre,
        });
        cache.insert(digest, v.clone());
        Ok(v)
    }
    pub(crate) fn call(
        &self,
        l: &Loaded,
        state: State,
        start: Instant,
        input: &Input,
        r: &[HttpResponse],
    ) -> (State, Result<Step, &'static str>, Metric) {
        let mut store = Store::new(&self.engine, state);
        store.data_mut().deadline = start + self.options.step_wall_clock;
        store.data_mut().memory = 0;
        store.limiter(|s| s);
        store.set_hostcall_fuel(4 << 20);
        store.set_max_component_handles(128);
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|mut ctx| {
            ctx.data_mut().checked()?;
            Ok(UpdateDeadline::Continue(1))
        });
        let result = (|| -> wasmtime::Result<Step> {
            store.set_fuel(self.options.fuel_per_step)?;
            store.data_mut().checked()?;
            let op = store.data().op.clone();
            macro_rules! call {
                ($guest:expr,$method:ident,$call:ident,$i:expr) => {
                    $guest.$method(
                        &mut store,
                        &$call {
                            input: $i.clone(),
                            responses: r.to_vec(),
                        },
                    )
                };
            }
            match &l.pre {
                Pre::Trade(pre) => {
                    let inst = pre.instantiate(&mut store)?;
                    let g = inst.kaivo_upstream_trade();
                    match input {
                        Input::Create(i) => call!(g, call_create_payment, CreateCall, i),
                        Input::Payment(i) if op == "close_payment" => {
                            call!(g, call_close_payment, PaymentCall, i)
                        }
                        Input::Payment(i) => call!(g, call_query_payment, PaymentCall, i),
                        Input::Refund(i) if op == "refund" => call!(g, call_refund, RefundCall, i),
                        Input::Refund(i) => call!(g, call_query_refund, RefundCall, i),
                        Input::Route(i) => call!(g, call_route_callback, RouteCall, i),
                        Input::Callback(i) => call!(g, call_verify_callback, CallbackCall, i),
                    }
                }
                Pre::Verify(pre) => {
                    let inst = pre.instantiate(&mut store)?;
                    let g = inst.kaivo_upstream_verification();
                    match input {
                        Input::Payment(i) => call!(g, call_query_payment, PaymentCall, i),
                        Input::Refund(i) => call!(g, call_query_refund, RefundCall, i),
                        _ => store.data_mut().fail("unsupported_operation"),
                    }
                }
            }
        })();
        let result = result
            .map_err(|e| {
                store
                    .data()
                    .fault
                    .unwrap_or_else(|| match e.downcast_ref::<Trap>() {
                        Some(Trap::OutOfFuel) => "fuel_exhausted",
                        Some(Trap::MemoryOutOfBounds) => "invalid_memory",
                        _ if e.is::<wasmtime::PoolConcurrencyLimitError>()
                            || e.is::<wasmtime::OutOfMemory>()
                            || e.is::<std::io::Error>() =>
                        {
                            "host_service"
                        }
                        _ => {
                            let diagnostic = e.root_cause().to_string();
                            if diagnostic.contains("pointer")
                                && (diagnostic.contains("bounds") || diagnostic.contains("aligned"))
                            {
                                "invalid_memory"
                            } else if diagnostic.contains("fuel allocated for hostcalls") {
                                "host_io_limit"
                            } else {
                                "sandbox_trap"
                            }
                        }
                    })
            })
            .and_then(|s| {
                store.data().check()?;
                Ok(s)
            });
        let metric = Metric {
            fuel: self.options.fuel_per_step - store.get_fuel().unwrap_or(0),
            memory: store.data().memory,
            elapsed: Duration::ZERO,
        };
        (store.into_data(), result, metric)
    }
}
pub(crate) enum Input {
    Create(CreatePaymentInput),
    Payment(PaymentInput),
    Refund(RefundInput),
    Route(RouteCallbackInput),
    Callback(CallbackInput),
}
#[derive(Default, Clone, Debug)]
pub struct Metric {
    pub fuel: u64,
    pub memory: usize,
    pub elapsed: Duration,
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    #[test]
    fn queued_wait_observes_cancellation_and_deadlines() {
        let gate = Admission::new(1);
        let held = gate.acquire(&Cancellation::default()).unwrap();
        let cancel = Cancellation::default();
        thread::scope(|scope| {
            let (tx, rx) = mpsc::channel();
            let gate = &gate;
            let shared = &cancel;
            let waiter = scope.spawn(move || {
                tx.send(()).unwrap();
                gate.acquire(shared).err()
            });
            rx.recv().unwrap();
            cancel.cancel();
            assert_eq!(waiter.join().unwrap(), Some("cancelled"));
        });
        let deadline = Cancellation {
            deadline: Some(Instant::now() + Duration::from_millis(10)),
            ..Default::default()
        };
        assert_eq!(gate.acquire(&deadline).err(), Some("cancelled"));
        drop(held);
        assert!(gate.acquire(&Cancellation::default()).is_ok());
    }
    #[test]
    fn allocator_exhaustion_is_a_host_failure() {
        use crate::{environment::SystemEnvironment, package::Package};
        let mut options = Options::replay("payment");
        options.pool_slots = 1;
        let host = Host::new(options).unwrap();
        let mut manifest: Manifest = serde_json::from_value(crate::tests::manifest()).unwrap();
        manifest.config.clear();
        manifest.secrets.clear();
        let package = Package {
            manifest,
            wasm: include_bytes!(concat!(env!("OUT_DIR"), "/trade-plugin.wasm")).to_vec(),
            fixtures: Default::default(),
        };
        let loaded = host.load(&package).unwrap();
        // Occupy the allocator directly to exercise the fallback behind admission.
        let env = Arc::new(SystemEnvironment);
        let state = State::new(
            loaded.manifest.clone(),
            env.clone(),
            Default::default(),
            "query_payment",
        );
        let mut store = Store::new(&host.engine, state);
        store.set_fuel(DEFAULT_FUEL).unwrap();
        store.set_epoch_deadline(1000);
        let Pre::Trade(pre) = &loaded.pre else {
            unreachable!()
        };
        let _occupied = pre.instantiate(&mut store).unwrap();
        let result = host.execute(
            &loaded,
            "query_payment",
            br#"{"order_id":"probe","money":{"amount":"1","currency":"CNY"}}"#,
            env,
            Default::default(),
        );
        assert_eq!(result.error_code.as_deref(), Some("host_service"));
        assert_eq!(result.category, "not_sent");
    }
    #[test]
    fn options_use_frozen_fuel_and_separate_live_and_replay_clocks() {
        assert_eq!(Options::production("payment").fuel_per_step, 50_000_000);
        assert_eq!(Options::replay("verification").fuel_per_step, 50_000_000);
        assert_eq!(
            Options::production("payment").step_wall_clock,
            Duration::from_millis(200)
        );
        let mut opts = Options::replay("payment");
        assert_eq!(opts.step_wall_clock, Duration::from_secs(5));
        opts.pool_slots = 1;
        opts.max_concurrent_steps = 8;
        assert_eq!(Host::new(opts).unwrap().options.max_concurrent_steps, 1);
    }
}
