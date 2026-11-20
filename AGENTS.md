# Kaivo upstream gateway development

- Work only in this repository. Preserve existing changes. Commit, push or change branches only when explicitly requested.
- Keep the host, SDK, WIT, release configuration, source closure and replay projections synchronized. Keep the two Cargo workspaces independent. Use Rust 1.99.1 and the tool versions in build-config.json.
- Keep all source, documentation and comments in English. Derive paths from arguments, checkout roots and operating-system temporary directories. Keep machine-specific caches and paths out of source, tools and CI.
- Generate test credentials in memory and use only synthetic or approved recorded data. Keep private keys, signatures, personal data and merchant credentials out of fixtures, reports, logs and source.
- Use integer minor units with a currency. The gateway translates protocols and classifies dispatch outcomes. Payment and reconciliation own approval, settlement and order state.
- Require exact component interfaces and closed-by-default egress. Keep development HTTP and uncommitted-source switches explicit. The transport implements one exchange with bounded reads, cancellation and no redirects or automatic retries.
- After changes run make bindings, check binding drift, and run make check plugins replay repro deny vet. Run bench, calibrate and stress after runtime or plugin changes. Record actual verification and outstanding work in PILOT_NOTES.md.
