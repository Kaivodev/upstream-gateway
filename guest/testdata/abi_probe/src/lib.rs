//! Purpose-built conformance component. Every mode is selected by test configuration.
use kaivo_upstream_sdk::trade::*;
use std::sync::atomic::{AtomicU32, Ordering};
struct Probe;
static VISITS: AtomicU32 = AtomicU32::new(0);
fn request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        url: "https://example.test/query".into(),
        headers: vec![],
        body: Vec::new(),
    }
}
fn fragments() -> String {
    let mut bytes = host::random(16);
    bytes.extend(host::random(16));
    String::from_utf8(bytes).unwrap()
}
impl Trade for Probe {
    fn query_payment(c: PaymentCall) -> Step {
        let mode = host::config("mode");
        let mut req = request();
        let mut id = "probe".to_string();
        match mode.as_str() {
            "loop" => loop {
                std::hint::spin_loop()
            },
            #[cfg(target_arch = "wasm32")]
            "memory" => {
                std::hint::black_box(core::arch::wasm32::memory_grow::<0>(513));
            }
            "calls" => {
                for _ in 0..128 {
                    host::now();
                }
            }
            "random" => {
                host::random(65537);
            }
            "random_total" => {
                for _ in 0..5 {
                    host::random(65536);
                }
            }
            "log_level" => {
                host::log("trace", "", &[]);
            }
            "log_count" => {
                for _ in 0..33 {
                    host::log("info", "", &[]);
                }
            }
            "log_size" => {
                host::log("info", &"a".repeat(8192), &[]);
            }
            "split_log" => {
                for _ in 0..2 {
                    host::log("info", &String::from_utf8(host::random(16)).unwrap(), &[]);
                }
            }
            "leak_log" => {
                host::log("info", &fragments(), &[]);
            }
            "leak_url" => {
                req.url.push_str(&fragments());
                return Step::Request(req);
            }
            "leak_body" => {
                req.body = fragments().into_bytes();
                return Step::Request(req);
            }
            "leak_header" => {
                req.headers.push(("X-Test".into(), vec![fragments()]));
                return Step::Request(req);
            }
            "leak_step" => id = fragments(),
            "undeclared" => {
                host::config("absent");
            }
            "clock" => {
                std::hint::black_box(std::time::SystemTime::now());
            }
            "fresh" => {
                if VISITS.fetch_add(1, Ordering::Relaxed) != 0 {
                    return error("dirty");
                }
                if c.responses.is_empty() {
                    return Step::Request(req);
                }
            }
            "fifth" | "missing_response" => return Step::Request(req),
            "reflect" => {
                host::log("info", "before reflected response", &[]);
                return Step::Request(req);
            }
            "after_request" if c.responses.is_empty() => {
                host::log("info", "before dispatch", &[]);
                return Step::Request(req);
            }
            "after_request" => return error("failed"),
            "rejected" => return Step::Result(OperationResult::Rejected("declined".into())),
            _ => {}
        }
        completed(Output::Payment(PaymentOutput {
            order_id: c.input.order_id,
            upstream_id: id,
            money: c.input.money,
            status: PaymentStatus::Paid,
            url: None,
            qrcode: None,
            paid_at: None,
            expires_at: None,
        }))
    }
    fn route_callback(_c: RouteCall) -> Step {
        match host::config("mode").as_str() {
            "crypto" => {
                host::sign("md5", None, &[]);
            }
            "http" => return Step::Request(request()),
            _ => {}
        }
        error("route")
    }
}
kaivo_upstream_sdk::export_trade!(Probe);
