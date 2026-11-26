use std::{ffi::OsString, path::PathBuf, time::Duration};

enum Command {
    Serve(PathBuf),
    Wrap(PathBuf, i32),
    Migrate(PathBuf, Option<upstream_gateway::AppRole>),
}

const USAGE: &str = "usage: upstream-gateway --config <path> | upstream-gateway migrate --config <path> [--app-role <lowercase_identifier>] | upstream-gateway wrap-kek --config <path> [--version <n>]";

fn command(args: impl IntoIterator<Item = OsString>) -> Result<Command, &'static str> {
    let mut args = args.into_iter().peekable();
    let subcommand = args.next_if(|a| a == "wrap-kek" || a == "migrate");
    let subcommand = subcommand.as_deref().and_then(|s| s.to_str());
    let mut app_role = None;
    let mut config = None;
    let mut version = None;
    while let Some(flag) = args.next() {
        if flag == "--config" && config.is_none() {
            config = Some(PathBuf::from(args.next().ok_or(USAGE)?));
        } else if subcommand == Some("migrate") && flag == "--app-role" && app_role.is_none() {
            let name = args.next().ok_or(USAGE)?;
            app_role = Some(name.to_str().ok_or("app role must be ASCII")?.parse()?);
        } else if subcommand == Some("wrap-kek") && flag == "--version" && version.is_none() {
            let n = args
                .next()
                .ok_or(USAGE)?
                .to_str()
                .ok_or(USAGE)?
                .parse::<i32>()
                .map_err(|_| USAGE)?;
            if n <= 0 {
                return Err(USAGE);
            }
            version = Some(n);
        } else {
            return Err(USAGE);
        }
    }
    let config = config.ok_or(USAGE)?;
    Ok(match subcommand {
        Some("wrap-kek") => Command::Wrap(config, version.unwrap_or(1)),
        Some("migrate") => Command::Migrate(config, app_role),
        _ => Command::Serve(config),
    })
}

fn main() -> std::process::ExitCode {
    let command = match command(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let runtime = tokio::runtime::Runtime::new().expect("create gateway runtime");
    let result = runtime.block_on(async {
        match command {
            Command::Serve(path) => upstream_gateway::run(&path).await,
            Command::Migrate(path, app_role) => {
                let version = upstream_gateway::migrate(&path, app_role.as_ref()).await?;
                let grants = if app_role.is_some() {
                    "applied"
                } else {
                    "skipped"
                };
                println!("schema version {version}, grants {grants}");
                Ok(())
            }
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
    fn migrate_accepts_only_a_single_plain_application_role() {
        let parse = |args: &[&str]| command(args.iter().map(OsString::from)).ok();
        assert!(matches!(
            parse(&["migrate", "--config", "instance"]),
            Some(Command::Migrate(_, None))
        ));
        for name in ["a", "_", "select", "_app01", &"a".repeat(63)] {
            assert!(
                matches!(parse(&["migrate", "--app-role", name, "--config", "instance"]),
                Some(Command::Migrate(p, Some(_))) if p == std::path::Path::new("instance"))
            );
        }
        for name in [
            "",
            "1app",
            "UPPER",
            "app-role",
            "two roles",
            "a.b",
            "a\"b",
            "app;",
            "é",
            &"a".repeat(64),
        ] {
            assert!(parse(&["migrate", "--config", "instance", "--app-role", name]).is_none());
        }
        for args in [
            &["migrate"][..],
            &["migrate", "--config"],
            &["migrate", "--app-role", "app"],
            &["migrate", "--config", "instance", "--app-role"],
            &[
                "migrate",
                "--config",
                "instance",
                "--app-role",
                "a",
                "--app-role",
                "b",
            ],
            &["migrate", "--config", "instance", "--version", "1"],
            &["--config", "instance", "--app-role", "app"],
            &["wrap-kek", "--config", "instance", "--app-role", "app"],
        ] {
            assert!(parse(args).is_none());
        }
    }

    #[test]
    fn accepts_existing_service_invocation_and_versioned_wrap() {
        let parse = |args: &[&str]| command(args.iter().map(OsString::from)).ok();
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
