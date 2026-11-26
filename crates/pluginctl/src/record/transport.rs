//! Capture the single mapi exchange against the selected loopback simulator.
use super::http::{FORM, Simulator};
use anyhow::{Result, ensure};
use base64::prelude::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, Cursor},
    sync::Mutex,
    time::{Duration, Instant},
};
use upstream_host::{
    environment::{Cancellation, Incoming, Transport},
    replay::{SignedQuery, normalized_exchange},
    types::HttpRequest,
};

pub(super) struct CaptureTransport {
    pub sim: Simulator,
    pub corrupt_signature: bool,
    pub exchanges: Mutex<Vec<Value>>,
}

impl CaptureTransport {
    fn post(
        &self,
        request: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<super::http::Response> {
        ensure!(
            request.method == "POST"
                && matches!(
                    request.headers.as_slice(), [(name, values)] if name.eq_ignore_ascii_case("Content-Type") && values == &[FORM]
                ),
            "unexpected mapi request"
        );
        let corrupted;
        let body = if self.corrupt_signature {
            corrupted = SignedQuery::parse(&request.body)?
                .replace_signature("00000000000000000000000000000000");
            &corrupted
        } else {
            &request.body
        };
        self.sim.post_form(&request.url, body, deadline, cancel)
    }
}

impl Transport for CaptureTransport {
    fn send(
        &self,
        template: &HttpRequest,
        request: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Incoming> {
        // Record the header, query and form templates. Only the simulator receives
        // the expanded request, even when transport fails.
        let mut exchange = json!({"request": normalized_exchange(template, request)});
        let result = self.post(
            request,
            deadline.min(Instant::now() + Duration::from_secs(2)),
            cancel,
        );
        match &result {
            Ok(r) => {
                exchange["response"] = json!({
                    "status": r.status, "headers": r.headers.iter().cloned().collect::<BTreeMap<_, _>>(),
                    "body": BASE64_STANDARD.encode(&r.body),
                })
            }
            Err(e) => {
                let timeout = e
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut);
                exchange["error"] = json!(if timeout {
                    "timeout"
                } else {
                    "transport_error"
                });
            }
        }
        self.exchanges.lock().unwrap().push(exchange);
        let response = result?;
        Ok(Incoming {
            status: response.status,
            headers: response.headers,
            body: Box::new(Cursor::new(response.body)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
    };
    use upstream_host::replay::{MARK, normalized};
    fn transport(origin: &str) -> CaptureTransport {
        CaptureTransport {
            sim: Simulator::parse(origin).unwrap(),
            corrupt_signature: true,
            exchanges: Mutex::default(),
        }
    }
    fn request(url: String) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            headers: vec![("Content-Type".into(), vec![FORM.into()])],
            body: b"z=a%2fb&%73ign=test-value&type=alipay".to_vec(),
            url,
        }
    }

    #[test]
    fn rejects_foreign_targets_before_connecting() {
        let t = transport("http://127.0.0.1:3456");
        for target in [
            "http://10.0.0.1:3456/",
            "http://127.0.0.1:3457/",
            "https://127.0.0.1:3456/",
        ] {
            // An expired deadline prevents socket I/O even if origin validation regresses.
            let r = request(target.into());
            let err = t
                .send(&r, &r, Instant::now(), &Cancellation::default())
                .err()
                .unwrap();
            assert!(err.downcast_ref::<io::Error>().is_none());
            assert_eq!(
                t.exchanges.lock().unwrap().last().unwrap()["error"],
                "transport_error"
            );
        }
    }

    #[test]
    fn corrupts_only_the_signature_and_records_the_normalized_request() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let t = transport(&origin);
        let mut template = request(format!("{origin}/mapi.php?key={{{{secret:shared}}}}"));
        template.body.extend_from_slice(b"&key={{secret:shared}}");
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let value = upstream_host::package::hex(&random);
        let mut r = request(format!("{origin}/mapi.php?key={value}"));
        r.body.extend_from_slice(format!("&key={value}").as_bytes());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);
            let mut length = None;
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            for line in reader.by_ref().lines() {
                let line = line.unwrap();
                if line.is_empty() {
                    break;
                }
                if let Some(n) = line.strip_prefix("Content-Length: ") {
                    length = n.parse::<usize>().ok();
                }
            }
            let mut body = vec![0; length.unwrap()];
            reader.read_exact(&mut body).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            (request_line, body)
        });
        let _ = t
            .send(
                &template,
                &r,
                Instant::now() + Duration::from_secs(2),
                &Cancellation::default(),
            )
            .unwrap();
        let (line, body) = server.join().unwrap();
        assert!(line == format!("POST /mapi.php?key={value} HTTP/1.1\r\n"));
        assert!(
            body == format!(
                "z=a%2fb&%73ign=00000000000000000000000000000000&type=alipay&key={value}"
            )
            .as_bytes()
        );
        let captured = &t.exchanges.lock().unwrap()[0]["request"];
        assert!(captured["url"] == template.url);
        let body = BASE64_STANDARD
            .decode(captured["body"].as_str().unwrap())
            .unwrap();
        assert!(
            body == format!("z=a%2fb&%73ign={MARK}&type=alipay&key={{{{secret:shared}}}}")
                .as_bytes()
        );
    }

    #[test]
    fn a_read_deadline_records_a_timeout_exchange() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let t = transport(&origin);
        let r = request(format!("{origin}/mapi.php"));
        // The listener completes the handshake but supplies no response.
        assert!(
            t.send(
                &r,
                &r,
                Instant::now() + Duration::from_millis(80),
                &Cancellation::default()
            )
            .is_err()
        );
        assert_eq!(
            *t.exchanges.lock().unwrap(),
            vec![json!({"request": normalized(&r), "error": "timeout"})]
        );
    }
}
