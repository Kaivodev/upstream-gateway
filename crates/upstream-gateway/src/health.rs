use futures_util::{Stream, stream};
use std::pin::Pin;
use tokio::sync::watch;
use tonic::{Request, Response, Status};

tonic::include_proto!("grpc.health.v1");
use health_check_response::ServingStatus;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Serving,
    Draining,
    RestartRequired,
}

#[derive(Clone)]
pub(crate) struct Health(pub watch::Receiver<Lifecycle>);

fn response(state: Lifecycle, known: bool) -> HealthCheckResponse {
    let status = match (known, state) {
        (false, _) => ServingStatus::ServiceUnknown,
        (true, Lifecycle::Serving) => ServingStatus::Serving,
        (true, _) => ServingStatus::NotServing,
    };
    HealthCheckResponse {
        status: status.into(),
    }
}

#[tonic::async_trait]
impl health_server::Health for Health {
    async fn check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        if !request.get_ref().service.is_empty() {
            return Err(Status::not_found("unknown service"));
        }
        Ok(Response::new(response(*self.0.borrow(), true)))
    }

    type WatchStream = Pin<Box<dyn Stream<Item = Result<HealthCheckResponse, Status>> + Send>>;

    async fn watch(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let known = request.get_ref().service.is_empty();
        let mut state = self.0.clone();
        state.mark_changed();
        let updates = stream::unfold(Some(state), move |rx| async move {
            let mut rx = rx?;
            rx.changed().await.ok()?;
            let value = *rx.borrow_and_update();
            // Finish open probes after the final update so graceful shutdown can complete.
            Some((
                Ok(response(value, known)),
                (value == Lifecycle::Serving).then_some(rx),
            ))
        });
        Ok(Response::new(Box::pin(updates)))
    }
}

#[cfg(test)]
mod tests {
    use super::{health_server::Health as _, *};
    use futures_util::StreamExt;

    #[tokio::test]
    async fn check_and_watch_follow_drain_and_fence() {
        for terminal in [Lifecycle::Draining, Lifecycle::RestartRequired] {
            let (tx, rx) = watch::channel(Lifecycle::Serving);
            let health = Health(rx);
            let probe = || Request::new(HealthCheckRequest::default());
            let mut updates = health.watch(probe()).await.unwrap().into_inner();
            assert_eq!(
                updates.next().await.unwrap().unwrap().status(),
                ServingStatus::Serving
            );
            assert_eq!(
                health.check(probe()).await.unwrap().into_inner().status(),
                ServingStatus::Serving
            );
            tx.send_replace(terminal);
            assert_eq!(
                health.check(probe()).await.unwrap().into_inner().status(),
                ServingStatus::NotServing
            );
            assert_eq!(
                updates.next().await.unwrap().unwrap().status(),
                ServingStatus::NotServing
            );
            assert!(updates.next().await.is_none());
            let unknown = || {
                Request::new(HealthCheckRequest {
                    service: "unknown".into(),
                })
            };
            assert_eq!(
                health.check(unknown()).await.unwrap_err().code(),
                tonic::Code::NotFound
            );
            let mut updates = health.watch(unknown()).await.unwrap().into_inner();
            assert_eq!(
                updates.next().await.unwrap().unwrap().status(),
                ServingStatus::ServiceUnknown
            );
        }
    }
}
