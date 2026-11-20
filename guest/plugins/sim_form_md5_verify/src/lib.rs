use kaivo_upstream_sdk::verification::*;
struct Plugin;
impl Verification for Plugin {
    fn query_payment(call: PaymentCall) -> Step {
        sim_form_md5_protocol::query_payment(call)
    }
    fn query_refund(call: RefundCall) -> Step {
        sim_form_md5_protocol::query_refund(call)
    }
}
kaivo_upstream_sdk::export_verification!(Plugin);
