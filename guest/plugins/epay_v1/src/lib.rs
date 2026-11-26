use kaivo_upstream_sdk::trade::*;

struct Plugin;

impl Trade for Plugin {
    fn create_payment(call: CreateCall) -> Step {
        epay_v1_protocol::trade::create(call)
    }

    fn query_payment(call: PaymentCall) -> Step {
        epay_v1_protocol::query_payment(call)
    }

    fn route_callback(call: RouteCall) -> Step {
        epay_v1_protocol::trade::route(call)
    }

    fn verify_callback(call: CallbackCall) -> Step {
        epay_v1_protocol::trade::verify(call)
    }
}

kaivo_upstream_sdk::export_trade!(Plugin);
