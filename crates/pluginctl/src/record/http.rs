//! Single-exchange HTTP/1.1 transport for the test control plane and callback listener.
use anyhow::{Context, Result, ensure};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
use upstream_host::{environment::Cancellation, package::token, types::Headers as WireHeaders};

pub(super) const TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_LIMIT: usize = 16 << 10;
const RESPONSE_LIMIT: usize = 1 << 20;
pub(super) const FORM: &str = "application/x-www-form-urlencoded";

#[derive(Clone, Copy)]
pub(super) struct Simulator {
    addr: SocketAddr,
}

impl Simulator {
    pub fn parse(origin: &str) -> Result<Self> {
        let authority = origin
            .strip_prefix("http://")
            .context("invalid simulator origin")?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        let port = authority
            .strip_prefix("127.0.0.1:")
            .or_else(|| authority.strip_prefix("[::1]:"))
            .context("invalid simulator origin")?;
        ensure!(
            !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
            "invalid simulator port"
        );
        let addr: SocketAddr = authority
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid simulator port"))?;
        ensure!(addr.port() != 0, "invalid simulator port");
        Ok(Self { addr })
    }

    pub fn target<'a>(&self, url: &'a str) -> Result<&'a str> {
        let rest = url
            .strip_prefix("http://")
            .context("invalid simulator URL")?;
        let slash = rest.find('/').context("missing simulator path")?;
        ensure!(
            Self::parse(&url[..7 + slash])?.addr == self.addr,
            "foreign simulator origin"
        );
        let path = &rest[slash..];
        check_target(path)?;
        Ok(path)
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        media: Option<&str>,
        body: &[u8],
    ) -> Result<Response> {
        let mut head = String::new();
        if let Some(token) = bearer {
            ensure!(
                token.len() >= 16 && token.bytes().all(|b| b.is_ascii_graphic()),
                "invalid simulator control token"
            );
            head.push_str("Authorization: Bearer ");
            head.push_str(token);
            head.push_str("\r\n");
        }
        if let Some(media) = media {
            head.push_str(&format!("Content-Type: {media}\r\n"));
        }
        self.exchange(
            method,
            path,
            &head,
            body,
            Instant::now() + TIMEOUT,
            &Cancellation::default(),
        )
    }

    pub(super) fn exchange(
        &self,
        method: &str,
        path: &str,
        headers: &str,
        body: &[u8],
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Response> {
        check_target(path)?;
        let stream = TcpStream::connect_timeout(&self.addr, remaining(deadline, cancel)?)?;
        let mut io = TimedSocket {
            stream: &stream,
            until: deadline,
            cancel,
        };
        write!(
            io,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n",
            self.addr,
            body.len()
        )?;
        io.write_all(body)?;
        read_response(&mut BufReader::new(io))
    }
}

fn check_target(path: &str) -> Result<()> {
    ensure!(
        path.starts_with('/')
            && !path.starts_with("//")
            && path
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'#' | b'\\')),
        "invalid request target"
    );
    Ok(())
}

fn remaining(deadline: Instant, cancel: &Cancellation) -> io::Result<Duration> {
    if cancel.cancelled() {
        return Err(io::Error::other("recording cancelled"));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

struct TimedSocket<'a> {
    stream: &'a TcpStream,
    until: Instant,
    cancel: &'a Cancellation,
}
impl TimedSocket<'_> {
    fn poll(
        &self,
        mut op: impl FnMut(&TcpStream, Duration) -> io::Result<usize>,
    ) -> io::Result<usize> {
        loop {
            let wait = remaining(self.until, self.cancel)?.min(Duration::from_millis(100));
            match op(self.stream, wait) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}
impl Read for TimedSocket<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.poll(|mut s, wait| {
            s.set_read_timeout(Some(wait))?;
            s.read(buf)
        })
    }
}
impl Write for TimedSocket<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.poll(|mut s, wait| {
            s.set_write_timeout(Some(wait))?;
            s.write(buf)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn line(r: &mut impl BufRead, budget: &mut usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let n = r.take(*budget as u64).read_until(b'\n', &mut bytes)?;
    ensure!(bytes.ends_with(b"\r\n"), "invalid or oversized HTTP line");
    *budget -= n;
    bytes.truncate(n - 2);
    Ok(bytes)
}

#[derive(Default)]
struct Headers {
    length: Option<usize>,
    chunked: bool,
    media: Vec<String>,
    values: std::collections::BTreeMap<String, Vec<String>>,
}
fn headers(r: &mut impl BufRead, budget: &mut usize) -> Result<Headers> {
    let mut h = Headers::default();
    loop {
        let bytes = line(r, budget)?;
        if bytes.is_empty() {
            break;
        }
        let (name, value) = header(&bytes)?;
        h.values
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.to_owned());
        if name.eq_ignore_ascii_case("Content-Length") {
            ensure!(
                !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_digit())
                    && h.length.is_none(),
                "invalid content length"
            );
            h.length = Some(value.parse().context("invalid content length")?);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            ensure!(
                !h.chunked && value.eq_ignore_ascii_case("chunked"),
                "unsupported transfer encoding"
            );
            h.chunked = true;
        } else if name.eq_ignore_ascii_case("Content-Encoding") {
            ensure!(
                value.eq_ignore_ascii_case("identity"),
                "unsupported content encoding"
            );
        } else if name.eq_ignore_ascii_case("Content-Type") {
            h.media.push(value.to_owned());
        }
    }
    ensure!(
        !(h.chunked && h.length.is_some()),
        "ambiguous message framing"
    );
    Ok(h)
}
fn header(bytes: &[u8]) -> Result<(&str, &str)> {
    let (name, value) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.split_once(':'))
        .context("invalid HTTP header")?;
    ensure!(
        token(name) && value.bytes().all(|b| b == b'\t' || b >= 32 && b != 127),
        "invalid HTTP header"
    );
    Ok((name, value.trim_matches([' ', '\t'])))
}
fn exact(r: &mut impl Read, length: usize, limit: usize) -> Result<Vec<u8>> {
    ensure!(length <= limit, "HTTP body too large");
    let mut body = vec![0; length];
    r.read_exact(&mut body)?;
    Ok(body)
}
fn chunked(r: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    // Bound chunk extensions, delimiters and trailers independently of decoded data.
    let mut budget = RESPONSE_LIMIT;
    loop {
        let info = line(r, &mut budget)?;
        let size = info.split(|&b| b == b';').next().unwrap();
        ensure!(
            !size.is_empty() && size.iter().all(u8::is_ascii_hexdigit),
            "invalid chunk size"
        );
        let size = usize::from_str_radix(std::str::from_utf8(size)?, 16)?;
        if size == 0 {
            let mut trailer_budget = HEADER_LIMIT;
            loop {
                let trailer = line(r, &mut trailer_budget)?;
                if trailer.is_empty() {
                    return Ok(body);
                }
                header(&trailer)?;
            }
        }
        ensure!(size <= RESPONSE_LIMIT - body.len(), "HTTP body too large");
        let start = body.len();
        body.resize(start + size, 0);
        r.read_exact(&mut body[start..])?;
        ensure!(line(r, &mut budget)?.is_empty(), "invalid chunk terminator");
    }
}
pub(super) struct Response {
    pub status: u16,
    pub headers: WireHeaders,
    pub body: Vec<u8>,
}
fn read_response(r: &mut impl BufRead) -> Result<Response> {
    let mut budget = HEADER_LIMIT;
    let status = line(r, &mut budget)?;
    let status = status
        .strip_prefix(b"HTTP/1.1 ")
        .context("invalid HTTP status line")?;
    let mut parts = status.splitn(2, |&b| b == b' ');
    let code = parts.next().unwrap();
    let reason = parts.next().context("invalid HTTP status line")?;
    ensure!(
        code.len() == 3
            && code.iter().all(u8::is_ascii_digit)
            && reason.iter().all(|&b| b == 9 || b >= 32 && b != 127),
        "invalid HTTP status line"
    );
    let status = std::str::from_utf8(code)?.parse()?;
    ensure!((100..=599).contains(&status), "invalid HTTP status");
    let h = headers(r, &mut budget)?;
    let body = if h.chunked {
        chunked(r)?
    } else if let Some(len) = h.length {
        exact(r, len, RESPONSE_LIMIT)?
    } else {
        let mut body = Vec::new();
        r.take(RESPONSE_LIMIT as u64 + 1).read_to_end(&mut body)?;
        ensure!(body.len() <= RESPONSE_LIMIT, "HTTP body too large");
        body
    };
    Ok(Response {
        status,
        headers: h.values.into_iter().collect(),
        body,
    })
}

pub(super) struct Callback {
    pub method: String,
    pub query: Vec<u8>,
    pub media: Vec<String>,
    pub body: Vec<u8>,
}
fn callback(r: &mut impl BufRead) -> Result<Callback> {
    let mut budget = HEADER_LIMIT;
    let request = line(r, &mut budget)?;
    let mut parts = request.split(|&b| b == b' ');
    let method = std::str::from_utf8(parts.next().unwrap())?;
    let target = parts.next().context("missing callback target")?;
    ensure!(
        token(method) && parts.next() == Some(b"HTTP/1.1") && parts.next().is_none(),
        "invalid callback request"
    );
    let mut target = target.splitn(2, |&b| b == b'?');
    let path = target.next().unwrap();
    let query = target.next().unwrap_or_default();
    ensure!(path == b"/callback", "unexpected callback path");
    let h = headers(r, &mut budget)?;
    ensure!(!h.chunked, "unsupported callback framing");
    let body = exact(r, h.length.unwrap_or(0), 64 << 10)?;
    Ok(Callback {
        method: method.into(),
        query: query.to_vec(),
        media: h.media,
        body,
    })
}
pub(super) fn accept(mut stream: TcpStream) -> Result<Callback> {
    // Accepted sockets can inherit the nonblocking listener flag on BSD.
    stream.set_nonblocking(false)?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let received = callback(&mut BufReader::new(TimedSocket {
        stream: &stream,
        until: Instant::now() + TIMEOUT,
        cancel: &Cancellation::default(),
    }));
    if received.is_err() {
        stream.write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        return received;
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nsuccess")?;
    received
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_requires_exact_loopback_literal_and_port() {
        let a = Simulator::parse("http://127.0.0.1:2345/").unwrap();
        assert!(Simulator::parse("http://[::1]:65535").is_ok());
        for url in [
            "http://localhost:80",
            "http://127.0.0.2:80",
            "http://127.0.0.1",
            "http://127.0.0.1:+80",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "https://127.0.0.1:80",
            "http://127.0.0.1:80//",
            "http://u@127.0.0.1:80",
            "http://127.0.0.1:80/?q",
            "http://127.0.0.1:80/#",
            "http://127.0.0.1:80/a",
            "http://[0:0:0:0:0:0:0:1]:80",
            "http://127.0.0.1:80@elsewhere",
        ] {
            assert!(Simulator::parse(url).is_err(), "{url}");
        }
        assert_eq!(
            a.target("http://127.0.0.1:2345/path?x=y").unwrap(),
            "/path?x=y"
        );
        for url in [
            "http://[::1]:2345/path",
            "http://127.0.0.1:2346/path",
            "http://127.0.0.1:2345@other/path",
            "http://127.0.0.1:2345/path\r\nX:y",
            "http://127.0.0.1:2345/#fragment",
        ] {
            assert!(a.target(url).is_err());
        }
    }

    #[test]
    fn response_framing_and_limits() {
        for raw in [
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n2;test=yes\r\nbc\r\n0\r\nX-End: ok\r\n\r\n",
        ] {
            let response = read_response(&mut raw.as_bytes()).unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"abc");
        }
        for raw in [
            "HTTP/1.1 2000 OK\r\n\r\n",
            "BAD 200 OK\r\n\r\n",
            "HTTP/1.1 20x OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nab\r\n0\r\n\r\n",
        ] {
            assert!(read_response(&mut raw.as_bytes()).is_err());
        }
    }

    #[test]
    fn callback_preserves_target_and_bounds_headers_and_body() {
        let c = callback(&mut b"GET /callback?z=%2f?+&a=1 HTTP/1.1\r\ncOnTent-TyPe: text/plain\r\nContent-Length: 3\r\n\r\nabc".as_slice()).unwrap();
        assert_eq!(c.query, b"z=%2f?+&a=1");
        assert_eq!(c.method, "GET");
        assert_eq!(c.media, ["text/plain"]);
        assert_eq!(c.body, b"abc");
        for line in [
            "GET /elsewhere HTTP/1.1\r\n\r\n".into(),
            "GET /callback HTTP/1.1\r\nContent-Length: 65537\r\n\r\n".into(),
            format!(
                "GET /callback HTTP/1.1\r\nX-Test: {}\r\n\r\n",
                "x".repeat(16384)
            ),
        ] {
            assert!(callback(&mut line.as_bytes()).is_err());
        }
    }
}
