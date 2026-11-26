use std::{ffi::OsString, path::PathBuf, time::Duration};

enum Command {
    Serve(PathBuf),
    Wrap(PathBuf, i32),
}

fn command(args: impl IntoIterator<Item = OsString>) -> Option<Command> {
    let mut args = args.into_iter().peekable();
    let wrap = args.next_if(|a| a == "wrap-kek").is_some();
    let mut config = None;
    let mut version = None;
    while let Some(flag) = args.next() {
        if flag == "--config" && config.is_none() {
            config = Some(PathBuf::from(args.next()?));
        } else if wrap && flag == "--version" && version.is_none() {
            let n = args.next()?.to_str()?.parse::<i32>().ok()?;
            if n <= 0 {
                return None;
            }
            version = Some(n);
        } else {
            return None;
        }
    }
    Some(if wrap {
        Command::Wrap(config?, version.unwrap_or(1))
    } else {
        Command::Serve(config?)
    })
}

fn main() -> std::process::ExitCode {
    let Some(command) = command(std::env::args_os().skip(1)) else {
        eprintln!(
            "usage: upstream-gateway --config <path> | upstream-gateway wrap-kek --config <path> [--version <n>]"
        );
        return std::process::ExitCode::FAILURE;
    };
    let runtime = tokio::runtime::Runtime::new().expect("create gateway runtime");
    let result = runtime.block_on(async {
        match command {
            Command::Serve(path) => upstream_gateway::run(&path).await,
            Command::Wrap(path, version) => {
                upstream_gateway::wrap_kek(&path, version, std::io::stdout().lock()).await
            }
        }
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gateway stopped: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_existing_service_invocation_and_versioned_wrap() {
        let parse = |args: &[&str]| command(args.iter().map(OsString::from));
        assert!(
            matches!(parse(&["--config", "instance"]), Some(Command::Serve(p)) if p == std::path::Path::new("instance"))
        );
        assert!(matches!(
            parse(&["wrap-kek", "--config", "instance"]),
            Some(Command::Wrap(_, 1))
        ));
        assert!(matches!(
            parse(&[
                "wrap-kek",
                "--version",
                "2147483647",
                "--config",
                "instance"
            ]),
            Some(Command::Wrap(_, i32::MAX))
        ));
        for args in [
            &["--config", "instance", "--version", "3"][..],
            &["wrap-kek", "--config"],
            &["wrap-kek", "--config", "instance", "--version", "0"],
            &[
                "wrap-kek",
                "--config",
                "instance",
                "--version",
                "2147483648",
            ],
            &["wrap-kek", "--config", "instance", "--config", "other"],
        ] {
            assert!(parse(args).is_none());
        }
    }
}
