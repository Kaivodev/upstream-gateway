//! Kaivo ABI v3 component execution and offline approval evidence.
pub mod trade {
    wasmtime::component::bindgen!({
        path:"../../wit",world:"trade-plugin",imports:{default:trappable},
        additional_derives:[serde::Serialize,serde::Deserialize],
    });
}
pub mod verification {
    wasmtime::component::bindgen!({
        path:"../../wit",world:"verification-plugin",imports:{default:trappable},
        with:{"kaivo:upstream/host":crate::trade::kaivo::upstream::host,
              "kaivo:upstream/types":crate::trade::exports::kaivo::upstream::types},
    });
}
pub use trade::exports::kaivo::upstream::types;
pub use trade::kaivo::upstream::host as imports;
pub mod engine;
pub mod environment;
pub mod execute;
pub mod http;
pub mod json;
pub mod package;
pub mod replay;
mod state;
#[cfg(test)]
mod tests;
