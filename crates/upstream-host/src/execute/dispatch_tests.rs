use super::*;
use crate::{
    environment::{Connection, Dispatch, Incoming, Transport, WireIncoming},
    package::Manifest,
};
use std::{io::Cursor, sync::Mutex, time::Duration};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Denied,
    Unconfirmed,
    Leak,
    ConnectError,
    Forbidden,
    Cancelled,
    SendError,
    SecondOpenFails,
}

type Receipt = (usize, Option<Vec<u8>>, String);
struct Fixture {
    scenario: Scenario,
    events: Mutex<Vec<&'static str>>,
    secret: Vec<u8>,
    receipts: Mutex<Vec<Receipt>>,
}
impl Environment for Fixture {
    fn authorize_dispatch(&self, _: usize, _: &HttpRequest) -> Dispatch {
        self.events.lock().unwrap().push("authorize");
        match self.scenario {
            Scenario::Denied => Dispatch::Denied("package_revoked"),
            Scenario::Unconfirmed => Dispatch::Unconfirmed,
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
struct Opened<'a>(&'a Fixture);
impl Drop for Opened<'_> {
    fn drop(&mut self) {
        self.0.events.lock().unwrap().push("drop");
    }
}
impl Connection for Opened<'_> {
    fn send_wire(
        self: Box<Self>,
        template: &HttpRequest,
        request: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> anyhow::Result<WireIncoming> {
        self.0.send_wire(template, request, deadline, cancel)
    }
}
impl Transport for Fixture {
    fn open(
        &self,
        template: &HttpRequest,
        _: Instant,
        cancel: &Cancellation,
    ) -> anyhow::Result<Box<dyn Connection + '_>> {
        assert!(template.url.ends_with("?key={{secret:key}}"));
        let mut events = self.events.lock().unwrap();
        let first = events.is_empty();
        events.push("open");
        match self.scenario {
            Scenario::Forbidden => Err(AddressForbidden.into()),
            Scenario::Cancelled => {
                cancel.cancel();
                Err(AddressForbidden.into())
            }
            Scenario::ConnectError => anyhow::bail!("connection refused"),
            Scenario::SecondOpenFails if !first => anyhow::bail!("connection refused"),
            _ => Ok(Box::new(Opened(self))),
        }
    }
    fn send(
        &self,
        _: &HttpRequest,
        request: &HttpRequest,
        _: Instant,
        _: &Cancellation,
    ) -> anyhow::Result<Incoming> {
        assert!(request.url.ends_with("?key=expanded"));
        self.events.lock().unwrap().push("send");
        if self.scenario == Scenario::SendError {
            anyhow::bail!("connection closed")
        }
        let body = if self.scenario == Scenario::Leak {
            self.secret.clone()
        } else {
            vec![]
        };
        Ok(Incoming {
            status: 200,
            headers: vec![],
            body: Box::new(Cursor::new(body)),
        })
    }
}
fn trial(scenario: Scenario) -> (Arc<Fixture>, Execution) {
    let mut secret = vec![0; 32];
    getrandom::fill(&mut secret).unwrap();
    let env = Arc::new(Fixture {
        scenario,
        events: Default::default(),
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
        url: "https://upstream.invalid/pay?key={{secret:key}}".into(),
        headers: vec![],
        body: vec![],
    };
    let send = |out: &mut Execution| {
        let mut expanded = Zeroizing::new(r.clone());
        expanded.url = "https://upstream.invalid/pay?key=expanded".into();
        exchange(
            &state,
            out,
            &r,
            expanded,
            &*env,
            Instant::now() + Duration::from_secs(1),
        )
    };
    if scenario == Scenario::SecondOpenFails {
        send(&mut out).unwrap();
        out.responses += 1;
    }
    let error = send(&mut out).unwrap_err();
    out.failed(error);
    (env, out)
}
#[test]
fn denied_is_not_sent() {
    let (e, x) = trial(Scenario::Denied);
    assert_eq!(
        (x.category.as_str(), x.requests, x.error_code.as_deref()),
        ("not_sent", 0, Some("package_revoked"))
    );
    assert_eq!(*e.events.lock().unwrap(), ["open", "authorize", "drop"]);
    assert!(e.receipts.lock().unwrap().is_empty());
}
#[test]
fn unconfirmed_counts_without_transport() {
    let (e, x) = trial(Scenario::Unconfirmed);
    assert_eq!((x.category.as_str(), x.requests), ("unknown", 1));
    assert_eq!(x.error_code.as_deref(), Some("dispatch_unconfirmed"));
    assert_eq!(*e.events.lock().unwrap(), ["open", "authorize", "drop"]);
    assert_eq!(e.receipts.lock().unwrap().len(), 1);
}
#[test]
fn leak_delivers_original_bytes() {
    let (e, x) = trial(Scenario::Leak);
    assert_eq!(x.error_code.as_deref(), Some("secret_leak"));
    let r = e.receipts.lock().unwrap();
    assert!(r[0].1.as_deref() == Some(e.secret.as_slice()));
    assert_eq!(r[0].2, "secret_leak");
}

#[test]
fn open_failures_skip_dispatch_and_receipt() {
    for (scenario, code) in [
        (Scenario::ConnectError, "transport_connect"),
        (Scenario::Forbidden, "address_forbidden"),
        (Scenario::Cancelled, "cancelled"),
    ] {
        let (e, x) = trial(scenario);
        assert_eq!(
            (
                x.category.as_str(),
                x.requests,
                x.responses,
                x.error_code.as_deref()
            ),
            ("not_sent", 0, 0, Some(code))
        );
        assert_eq!(*e.events.lock().unwrap(), ["open"]);
        assert!(e.receipts.lock().unwrap().is_empty());
    }
}

#[test]
fn failed_send_records_one_unknown_attempt() {
    let (e, x) = trial(Scenario::SendError);
    assert_eq!(
        (x.category.as_str(), x.requests, x.error_code.as_deref()),
        ("unknown", 1, Some("transport_error"))
    );
    assert_eq!(
        *e.events.lock().unwrap(),
        ["open", "authorize", "send", "drop"]
    );
    assert_eq!(
        *e.receipts.lock().unwrap(),
        [(1, None, "transport_error".into())]
    );
}

#[test]
fn later_open_failure_preserves_prior_dispatch() {
    let (e, x) = trial(Scenario::SecondOpenFails);
    assert_eq!(
        (
            x.category.as_str(),
            x.requests,
            x.responses,
            x.error_code.as_deref()
        ),
        ("unknown", 1, 1, Some("transport_connect"))
    );
    assert_eq!(
        *e.events.lock().unwrap(),
        ["open", "authorize", "send", "drop", "open"]
    );
    assert_eq!(
        *e.receipts.lock().unwrap(),
        [(1, Some(vec![]), String::new())]
    );
}
