use kaivo_upstream_sdk::verification::*;

struct Plugin;

impl Verification for Plugin {
    fn query_payment(call: PaymentCall) -> Step {
        epay_v1_protocol::query_payment(call)
    }
}

kaivo_upstream_sdk::export_verification!(Plugin);
