//! SDK for bare WebAssembly components. On wasm32-unknown-unknown there is no OS:
//! SystemTime::now() and thread creation panic, files fail, println! has no output,
//! and HashMap keys use fixed seeds. Use host imports for time, entropy and logging.
#[cfg(all(feature = "trade", feature = "verification"))]
compile_error!("Select exactly one component world per build invocation");
pub mod form;
pub mod json;
pub mod time;

pub fn valid_money(amount: &str, currency: &str) -> bool {
    (1..=78).contains(&amount.len())
        && amount.bytes().all(|b| b.is_ascii_digit())
        && (amount == "0" || !amount.starts_with('0'))
        && (3..=12).contains(&currency.len())
        && currency.as_bytes()[0].is_ascii_uppercase()
        && currency
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
pub fn cny_minor(amount: &str, currency: &str) -> Option<i64> {
    (currency == "CNY" && valid_money(amount, currency))
        .then(|| amount.parse().ok())
        .flatten()
        .filter(|n| *n > 0)
}

#[cfg(any(feature = "trade", feature = "verification"))]
macro_rules! world_helpers {
    () => {
        pub fn request(request: HttpRequest) -> Step {
            Step::Request(request)
        }
        pub fn rejected(code: String) -> Step {
            Step::Result(OperationResult::Rejected(code))
        }
        pub fn unknown(code: Option<String>) -> Step {
            Step::Result(OperationResult::Unknown(code))
        }
        pub fn parse_utc_time(raw: &str) -> Option<host::UtcTime> {
            let (seconds, nanos) = crate::time::parse(raw)?;
            Some(host::UtcTime { seconds, nanos })
        }
        pub fn format_utc_time(t: host::UtcTime) -> Option<String> {
            crate::time::format((t.seconds, t.nanos))
        }
        pub fn error(code: &str) -> Step {
            Step::Result(OperationResult::Error(Some(code.into())))
        }
        pub fn completed(value: Output) -> Step {
            Step::Result(OperationResult::Completed(Completion { value, code: None }))
        }
    };
}

/// Retain the complete import interface even when the linker removes unused code.
#[doc(hidden)]
#[macro_export]
macro_rules! __retain_host {
    ($host:path) => {
        const _: () = {
            use $host as host;
            #[used]
            static CONFIG: fn(&str) -> String = host::config;
            #[used]
            static SIGN: fn(&str, Option<&str>, &[host::Part]) -> String = host::sign;
            #[used]
            static VERIFY: fn(&str, &str, &[host::Part], &str) -> bool = host::verify;
            #[used]
            static EQUAL: fn(&str, &str) -> bool = host::equal;
            #[used]
            static LOG: fn(&str, &str, &[(String, String)]) -> bool = host::log;
            #[used]
            static NOW: fn() -> host::UtcTime = host::now;
            #[used]
            static RANDOM: fn(u32) -> Vec<u8> = host::random;
        };
    };
}
#[cfg(feature="trade")]
#[rustfmt::skip]
#[allow(unsafe_op_in_unsafe_fn,clippy::all)]
pub mod trade_plugin;
#[cfg(feature = "trade")]
pub mod trade {
    pub use super::trade_plugin::exports::kaivo::upstream::types::*;
    pub use super::trade_plugin::kaivo::upstream::host;
    world_helpers!();
    pub trait Trade {
        fn create_payment(_call: CreateCall) -> Step {
            error("unsupported_operation")
        }
        fn query_payment(_call: PaymentCall) -> Step {
            error("unsupported_operation")
        }
        fn close_payment(_call: PaymentCall) -> Step {
            error("unsupported_operation")
        }
        fn refund(_call: RefundCall) -> Step {
            error("unsupported_operation")
        }
        fn query_refund(_call: RefundCall) -> Step {
            error("unsupported_operation")
        }
        fn route_callback(_call: RouteCall) -> Step {
            error("unsupported_operation")
        }
        fn verify_callback(_call: CallbackCall) -> Step {
            error("unsupported_operation")
        }
    }
}
#[cfg(feature = "trade")]
#[macro_export]
macro_rules! export_trade {
    ($ty:ident) => {
        $crate::__retain_host!($crate::trade::host);
        impl $crate::trade_plugin::exports::kaivo::upstream::trade::Guest for $ty {
            fn query_payment(call: $crate::trade::PaymentCall) -> $crate::trade::Step {
                <Self as $crate::trade::Trade>::query_payment(call)
            }
            fn query_refund(call: $crate::trade::RefundCall) -> $crate::trade::Step {
                <Self as $crate::trade::Trade>::query_refund(call)
            }
            fn create_payment(call: $crate::trade::CreateCall) -> $crate::trade::Step {
                <Self as $crate::trade::Trade>::create_payment(call)
            }
            fn close_payment(call: $crate::trade::PaymentCall) -> $crate::trade::Step {
                <Self as $crate::trade::Trade>::close_payment(call)
            }
            fn refund(call: $crate::trade::RefundCall) -> $crate::trade::Step {
                <Self as $crate::trade::Trade>::refund(call)
            }
            fn route_callback(call: $crate::trade::RouteCall) -> $crate::trade::Step {
                <Self as $crate::trade::Trade>::route_callback(call)
            }
            fn verify_callback(call: $crate::trade::CallbackCall) -> $crate::trade::Step {
                <Self as $crate::trade::Trade>::verify_callback(call)
            }
        }
        $crate::trade_plugin::export_generated_trade!($ty with_types_in $crate::trade_plugin);
    };
}

#[cfg(feature="verification")]
#[rustfmt::skip]
#[allow(unsafe_op_in_unsafe_fn,clippy::all)]
pub mod verification_plugin;
#[cfg(feature = "verification")]
pub mod verification {
    pub use super::verification_plugin::exports::kaivo::upstream::types::*;
    pub use super::verification_plugin::kaivo::upstream::host;
    world_helpers!();
    pub trait Verification {
        fn query_payment(_call: PaymentCall) -> Step {
            error("unsupported_operation")
        }
        fn query_refund(_call: RefundCall) -> Step {
            error("unsupported_operation")
        }
    }
}
#[cfg(feature = "verification")]
#[macro_export]
macro_rules! export_verification {
    ($ty:ident) => {
        $crate::__retain_host!($crate::verification::host);
        impl $crate::verification_plugin::exports::kaivo::upstream::verification::Guest for $ty {
            fn query_payment(call: $crate::verification::PaymentCall) -> $crate::verification::Step {
                <Self as $crate::verification::Verification>::query_payment(call)
            }
            fn query_refund(call: $crate::verification::RefundCall) -> $crate::verification::Step {
                <Self as $crate::verification::Verification>::query_refund(call)
            }
        }
        $crate::verification_plugin::export_generated_verification!($ty with_types_in $crate::verification_plugin);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_money_and_times() {
        assert!(valid_money(&"9".repeat(78), "USD"));
        assert!(!valid_money(&"9".repeat(79), "USD"));
        assert!(!valid_money("01", "CNY"));
        assert!(cny_minor("9223372036854775808", "CNY").is_none());
        for s in [
            "0001-01-01T00:00:00Z",
            "1969-12-31T23:59:59.000000001Z",
            "2000-02-29T12:34:56.01Z",
            "9999-12-31T23:59:59.999999999Z",
        ] {
            assert_eq!(time::format(time::parse(s).unwrap()).as_deref(), Some(s))
        }
        assert_eq!(time::parse("1970-01-01T01:00:00+01:00"), Some((0, 0)));
        assert!(time::parse("1900-02-29T00:00:00Z").is_none());
        assert!(time::parse("0000-01-01T00:00:00Z").is_none());
    }
    #[test]
    fn byte_exact_forms() {
        let v = form::parse(b"z=%FF&a+b=2&a+b=1&~=x%2Fy&blank").unwrap();
        assert_eq!(form::encode(&v), "a+b=2&a+b=1&blank=&z=%FF&~=x%2Fy");
        assert!(form::canonical(&v).is_none());
        for s in [b"a;%".as_slice(), b"%Z1"] {
            assert!(form::parse(s).is_none())
        }
        assert_eq!(form::path_escape("a+b/c@d"), "a+b%2Fc@d");
    }
    #[cfg(feature = "trade")]
    #[test]
    fn default_is_exact_unsupported_result() {
        use crate::trade::*;
        struct Empty;
        impl Trade for Empty {}
        let step = Empty::query_payment(PaymentCall {
            input: PaymentInput {
                order_id: "probe".into(),
                money: Money {
                    amount: "1".into(),
                    currency: "CNY".into(),
                },
            },
            responses: vec![],
        });
        assert!(
            matches!(step,Step::Result(OperationResult::Error(Some(code))) if code=="unsupported_operation")
        );
    }
}
