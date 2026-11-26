pub mod api {
    tonic::include_proto!("aipay.upstream.v1");
}

pub static DESCRIPTOR: &[u8] = tonic::include_file_descriptor_set!("upstream");

pub mod crypto;
mod db;
pub mod egress;
mod encoding;
pub mod wire;
pub use db::pool;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Trade,
    Verification,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Trade => "trade",
            Self::Verification => "verification",
        }
    }
    fn caller(self) -> &'static str {
        match self {
            Self::Trade => "payment",
            Self::Verification => "reconciliation",
        }
    }
    fn world(self) -> &'static str {
        match self {
            Self::Trade => "payment",
            Self::Verification => "verification",
        }
    }
}
#[derive(Clone, Copy)]
pub enum Mode {
    Production,
    Development {
        allow_loopback_http: bool,
        allow_private_http: bool,
        allow_uncommitted: bool,
    },
}
impl Mode {
    fn allow_http(self) -> bool {
        matches!(
            self,
            Self::Development {
                allow_loopback_http: true,
                ..
            } | Self::Development {
                allow_private_http: true,
                ..
            }
        )
    }
    fn allow_uncommitted(self) -> bool {
        matches!(
            self,
            Self::Development {
                allow_uncommitted: true,
                ..
            }
        )
    }
}

mod config;
mod health;
mod server;
mod service_token;
mod tls;
pub use server::run;
pub use tls::VerifiedCaller;

mod admin;
mod business;
mod callback;
mod journal;
mod service;
pub use service::{Events, Gateway};

#[cfg(test)]
mod integration;
#[cfg(test)]
mod tests;
