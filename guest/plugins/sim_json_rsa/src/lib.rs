use kaivo_upstream_sdk::trade::*;
struct Plugin;
impl Trade for Plugin {
    fn create_payment(call: CreateCall) -> Step {
        sim_json_rsa_protocol::create_payment(call)
    }
    fn query_payment(call: PaymentCall) -> Step {
        sim_json_rsa_protocol::query_payment(call)
    }
    fn close_payment(call: PaymentCall) -> Step {
        sim_json_rsa_protocol::close_payment(call)
    }
    fn refund(call: RefundCall) -> Step {
        sim_json_rsa_protocol::refund(call)
    }
    fn query_refund(call: RefundCall) -> Step {
        sim_json_rsa_protocol::query_refund(call)
    }
    fn route_callback(call: RouteCall) -> Step {
        sim_json_rsa_protocol::route_callback(call)
    }
    fn verify_callback(call: CallbackCall) -> Step {
        sim_json_rsa_protocol::verify_callback(call)
    }
}
kaivo_upstream_sdk::export_trade!(Plugin);
