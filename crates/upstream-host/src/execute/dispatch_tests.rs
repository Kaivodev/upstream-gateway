use super::*;
use crate::{
    environment::{Dispatch, Incoming, Transport},
    package::Manifest,
};
use std::{
    io::Cursor,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

type Receipt = (usize, Option<Vec<u8>>, String);
struct Fixture {
    action: u8,
    calls: AtomicUsize,
    secret: Vec<u8>,
    receipts: std::sync::Mutex<Vec<Receipt>>,
}
impl Environment for Fixture {
    fn authorize_dispatch(&self, _: usize, _: &HttpRequest) -> Dispatch {
        match self.action {
            0 => Dispatch::Denied("package_revoked"),
            1 => Dispatch::Unconfirmed,
            _ => Dispatch::Granted,
        }
    }
    fn record_attempt(
        &self,
        n: usize,
        _: &HttpRequest,
        r: Option<&CapturedResponse>,
        code: &str,
    ) -> anyhow::Result<()> {
        self.receipts
            .lock()
            .unwrap()
            .push((n, r.map(|r| r.body.clone()), code.into()));
        Ok(())
    }
}
impl Transport for Fixture {
    fn send(
        &self,
        _: &HttpRequest,
        _: &HttpRequest,
        _: Instant,
        _: &Cancellation,
    ) -> anyhow::Result<Incoming> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Incoming {
            status: 200,
            headers: vec![],
            body: Box::new(Cursor::new(self.secret.clone())),
        })
    }
}
fn trial(action: u8) -> (Arc<Fixture>, Execution) {
    let mut secret = vec![0; 32];
    getrandom::fill(&mut secret).unwrap();
    let env = Arc::new(Fixture {
        action,
        calls: 0.into(),
        secret,
        receipts: Default::default(),
    });
    let m = Manifest::parse(&crate::json::canonical(&crate::tests::manifest())).unwrap();
    let mut state = State::new(
        Arc::new(m),
        env.clone(),
        Default::default(),
        "query_payment",
    );
    state.scan.add(&env.secret);
    let mut out = Execution::default();
    let r = HttpRequest {
        method: "GET".into(),
        url: "https://example.test".into(),
        headers: vec![],
        body: vec![],
    };
    let res = exchange(
        &state,
        &mut out,
        &r,
        Zeroizing::new(r.clone()),
        &*env,
        Instant::now() + Duration::from_secs(1),
    );
    out.failed(res.err().unwrap());
    (env, out)
}
#[test]
fn denied_is_not_sent() {
    let (e, x) = trial(0);
    assert_eq!(
        (
            x.category.as_str(),
            x.requests,
            e.calls.load(Ordering::SeqCst)
        ),
        ("not_sent", 0, 0)
    );
    assert!(e.receipts.lock().unwrap().is_empty());
}
#[test]
fn unconfirmed_counts_without_transport() {
    let (e, x) = trial(1);
    assert_eq!(
        (
            x.category.as_str(),
            x.requests,
            e.calls.load(Ordering::SeqCst)
        ),
        ("unknown", 1, 0)
    );
    assert_eq!(x.error_code.as_deref(), Some("dispatch_unconfirmed"));
    assert_eq!(e.receipts.lock().unwrap().len(), 1);
}
#[test]
fn leak_delivers_original_bytes() {
    let (e, x) = trial(2);
    assert_eq!(x.error_code.as_deref(), Some("secret_leak"));
    let r = e.receipts.lock().unwrap();
    assert!(r[0].1.as_deref() == Some(e.secret.as_slice()));
    assert_eq!(r[0].2, "secret_leak");
}
