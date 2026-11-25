use std::{path::PathBuf, time::Duration};
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(flag), Some(file), None) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: upstream-gateway --config <path>");
        return std::process::ExitCode::FAILURE;
    };
    if flag != "--config" {
        eprintln!("usage: upstream-gateway --config <path>");
        return std::process::ExitCode::FAILURE;
    }
    let runtime = tokio::runtime::Runtime::new().expect("create gateway runtime");
    let result = runtime.block_on(upstream_gateway::run(&PathBuf::from(file)));
    runtime.shutdown_timeout(Duration::from_secs(1));
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gateway stopped: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
