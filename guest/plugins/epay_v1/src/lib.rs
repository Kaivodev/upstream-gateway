mod protocol;

use kaivo_upstream_sdk::trade::*;
use protocol::Config;

struct Plugin;

impl Plugin {
    fn configured(operation: impl FnOnce(&Config) -> Step) -> Step {
        let Some(config) = Config::new(
            host::config("gateway"),
            host::config("pid"),
            host::config("product_name"),
        ) else {
            return error("config");
        };
        operation(&config)
    }

    fn sign(canonical: Vec<u8>) -> String {
        host::sign(
            "md5",
            None,
            &[
                host::Part::Data(canonical),
                host::Part::Secret("merchant_key".into()),
            ],
        )
    }
}

impl Trade for Plugin {
    fn create_payment(call: CreateCall) -> Step {
        Self::configured(|config| protocol::create_payment(call, config, Self::sign))
    }

    fn route_callback(call: RouteCall) -> Step {
        Self::configured(|_| protocol::route_callback(call))
    }

    fn verify_callback(call: CallbackCall) -> Step {
        Self::configured(|config| protocol::verify_callback(call, config, Self::sign, host::equal))
    }
}

kaivo_upstream_sdk::export_trade!(Plugin);
