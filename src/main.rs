use clap::{CommandFactory, FromArgMatches, parser::ValueSource};
use tracing::{Level, debug, info};
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{
    Layer, filter::filter_fn, fmt, prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use nrev::{
    cli::{Cli, Command, ProgressMode, ScanArgSources},
    config::{HostConfig, NeighborConfig, PingConfig, ScanConfig, TraceConfig},
    data::DataRegistry,
    host::{HostScanEvent, HostScanner, resolve_host_targets},
    model::{EndpointState, HostScanTimings, ScanTimings},
    neighbor::resolve_neighbor,
    output::{
        render_human_host_report, render_human_neighbor_report, render_human_ping_report,
        render_human_probe_catalog, render_human_recipe_catalog, render_human_scan_report,
        render_human_trace_report, write_json_host_report, write_json_neighbor_report,
        write_json_ping_report, write_json_report, write_json_trace_report,
    },
    ping::run_ping,
    scanner::{ScanEvent, Scanner},
    target::TargetResolver,
    trace::run_trace,
    transport::SocketConnector,
};

#[tokio::main]
async fn main() {
    let exit_code = match run().await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("nrev: {error}");
            1
        }
    };
    std::process::exit(exit_code);
}

async fn run() -> anyhow::Result<()> {
    let command = Cli::command();
    let matches = command.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    let (progress_mode, quiet) = command_logging_mode(&cli.command);
    init_logging(progress_mode, quiet)?;
    match cli.command {
        Command::Port(args) => {
            let started = std::time::Instant::now();
            let registry = DataRegistry::load(args.data.as_deref())?;
            let arg_sources = scan_arg_sources(matches.subcommand_matches("port"));
            let config = ScanConfig::from_scan_args_with_sources(&args, &registry, &arg_sources)?;
            debug!(
                transport = %config.transport.as_str(),
                concurrency = config.concurrency,
                connect_timeout_ms = config.connect_timeout.as_millis(),
                probe_timeout_ms = config.probe_timeout.as_millis(),
                retries = config.retries,
                "Port scan configuration resolved"
            );
            progress(
                config.progress_mode,
                config.quiet,
                &format!("nrev v{} started", env!("CARGO_PKG_VERSION")),
            );

            let target_resolution_started = std::time::Instant::now();
            let targets =
                TargetResolver::new(config.default_ports.clone()).resolve(&args.targets)?;
            let target_resolution_time = target_resolution_started.elapsed();
            let target_count = targets.len();
            let requested_port_count: usize = targets.iter().map(|(_, ports)| ports.len()).sum();
            progress(
                config.progress_mode,
                config.quiet,
                &format!(
                    "Resolved {target_count} host(s), {requested_port_count} port assignment(s) in {}",
                    format_duration(target_resolution_time)
                ),
            );

            let mut execution = Scanner::new(config.clone(), registry, SocketConnector)
                .scan_with_progress(targets, |event| log_scan_event(config.quiet, event))
                .await?;
            execution.report.metadata.timings = Some(ScanTimings {
                target_resolution: target_resolution_time,
                transport_scan: execution.transport_scan_time,
                followup_probes: execution.followup_probe_time,
                total: started.elapsed(),
            });

            log_open_port_summary(config.quiet, &execution.report);

            if args.format.is_json() {
                let json = serde_json::to_string_pretty(&execution.report)?;
                println!("{json}");
            } else {
                print!(
                    "{}",
                    render_human_scan_report(&execution.report, config.show_all_states)
                );
            }

            progress(
                config.progress_mode,
                config.quiet,
                &format!(
                    "nrev v{} completed in {}",
                    env!("CARGO_PKG_VERSION"),
                    format_duration(
                        execution
                            .report
                            .metadata
                            .timings
                            .as_ref()
                            .map(|timings| timings.total)
                            .unwrap_or_else(|| started.elapsed())
                    )
                ),
            );

            if let Some(path) = &args.output {
                write_json_report(&execution.report, path)?;
            }
        }
        Command::Host(args) => {
            let started = std::time::Instant::now();
            let config = HostConfig::from_host_args(&args)?;
            debug!(
                method = %config.method.as_str(),
                concurrency = config.concurrency,
                timeout_ms = config.timeout.as_millis(),
                "Host scan configuration resolved"
            );
            progress(
                config.progress_mode,
                config.quiet,
                &format!("nrev v{} started", env!("CARGO_PKG_VERSION")),
            );

            let target_resolution_started = std::time::Instant::now();
            let targets = resolve_host_targets(&args.targets)?;
            let target_resolution_time = target_resolution_started.elapsed();
            progress(
                config.progress_mode,
                config.quiet,
                &format!(
                    "Resolved {} host(s) in {}",
                    targets.len(),
                    format_duration(target_resolution_time)
                ),
            );

            let mut execution = HostScanner::new(config.clone())
                .discover_with_progress(targets, |event| log_host_scan_event(config.quiet, event))
                .await?;
            execution.report.metadata.timings = Some(HostScanTimings {
                target_resolution: target_resolution_time,
                discovery: execution.discovery_time,
                total: started.elapsed(),
            });

            log_reachable_host_summary(config.quiet, &execution.report);

            if args.format.is_json() {
                println!("{}", serde_json::to_string_pretty(&execution.report)?);
            } else {
                print!(
                    "{}",
                    render_human_host_report(&execution.report, config.show_all_hosts)
                );
            }

            progress(
                config.progress_mode,
                config.quiet,
                &format!(
                    "nrev v{} completed in {}",
                    env!("CARGO_PKG_VERSION"),
                    format_duration(
                        execution
                            .report
                            .metadata
                            .timings
                            .as_ref()
                            .map(|timings| timings.total)
                            .unwrap_or_else(|| started.elapsed())
                    )
                ),
            );

            if let Some(path) = &args.output {
                write_json_host_report(&execution.report, path)?;
            }
        }
        Command::Ping(args) => {
            let config = PingConfig::from_ping_args(&args);
            let report = run_ping(&args.target, &config).await?;
            if args.format.is_json() {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", render_human_ping_report(&report));
            }
            if let Some(path) = &args.output {
                write_json_ping_report(&report, path)?;
            }
        }
        Command::Trace(args) => {
            let config = TraceConfig::from_trace_args(&args);
            let report = run_trace(&args.target, &config).await?;
            if args.format.is_json() {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", render_human_trace_report(&report));
            }
            if let Some(path) = &args.output {
                write_json_trace_report(&report, path)?;
            }
        }
        Command::Nei(args) => {
            let config = NeighborConfig::from_neighbor_args(&args);
            let report = resolve_neighbor(&args.target, &config).await?;
            if args.format.is_json() {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", render_human_neighbor_report(&report));
            }
            if let Some(path) = &args.output {
                write_json_neighbor_report(&report, path)?;
            }
        }
        Command::Probe(args) => {
            let registry = DataRegistry::load(args.data.as_deref())?;
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "builtin": registry.builtin_catalog(),
                        "external": registry.external_probes,
                    }))?
                );
            } else {
                print!(
                    "{}",
                    render_human_probe_catalog(
                        registry.builtin_catalog().probes(),
                        &registry.external_probes,
                    )
                );
            }
        }
        Command::Recipe(args) => {
            let registry = DataRegistry::load(args.data.as_deref())?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&registry.recipes)?);
            } else {
                print!("{}", render_human_recipe_catalog(&registry.recipes));
            }
        }
    }

    Ok(())
}

fn progress(progress_mode: ProgressMode, quiet: bool, message: &str) {
    let _ = progress_mode;
    let _ = quiet;
    info!("{message}");
}

fn log_scan_event(quiet: bool, event: ScanEvent) {
    match event {
        ScanEvent::TransportScanStarted {
            target_count,
            port_count,
            transport,
        } => progress(
            ProgressMode::Auto,
            quiet,
            &format!(
                "Starting {} transport scan on {target_count} host(s), {port_count} port(s)",
                transport.as_str().to_uppercase()
            ),
        ),
        ScanEvent::TransportScanCompleted { elapsed } => progress(
            ProgressMode::Auto,
            quiet,
            &format!("Transport scan completed in {}", format_duration(elapsed)),
        ),
        ScanEvent::FollowupProbesStarted {
            open_endpoint_count,
        } => progress(
            ProgressMode::Auto,
            quiet,
            &format!("Starting follow-up probes on {open_endpoint_count} open endpoint(s)"),
        ),
        ScanEvent::FollowupProbesCompleted { elapsed } => progress(
            ProgressMode::Auto,
            quiet,
            &format!("Follow-up probes completed in {}", format_duration(elapsed)),
        ),
    }
}

fn command_logging_mode(command: &Command) -> (ProgressMode, bool) {
    match command {
        Command::Port(args) => (args.progress, args.quiet),
        Command::Host(args) => (args.progress, args.quiet),
        Command::Ping(args) => (args.progress, args.quiet),
        Command::Trace(args) => (args.progress, args.quiet),
        Command::Nei(_) | Command::Probe(_) | Command::Recipe(_) => (ProgressMode::Quiet, true),
    }
}

fn init_logging(progress_mode: ProgressMode, quiet: bool) -> anyhow::Result<()> {
    let allow_debug = !quiet && progress_mode == ProgressMode::Verbose;
    let allow_info = !quiet && progress_mode != ProgressMode::Quiet;

    let filter = filter_fn(move |metadata| {
        if !metadata.target().starts_with("nrev") {
            return false;
        }

        match *metadata.level() {
            Level::ERROR => true,
            Level::INFO => allow_info,
            Level::DEBUG => allow_debug,
            Level::WARN | Level::TRACE => false,
        }
    });

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_timer(ChronoLocal::new("%H:%M:%S%.3f%:z".to_string()))
                .with_filter(filter),
        )
        .try_init()?;

    Ok(())
}

fn log_host_scan_event(quiet: bool, event: HostScanEvent) {
    match event {
        HostScanEvent::DiscoveryStarted {
            target_count,
            method,
        } => progress(
            ProgressMode::Auto,
            quiet,
            &format!(
                "Starting {} host scan on {target_count} host(s)",
                method.as_str().to_uppercase()
            ),
        ),
        HostScanEvent::DiscoveryCompleted { elapsed } => progress(
            ProgressMode::Auto,
            quiet,
            &format!("Host scan completed in {}", format_duration(elapsed)),
        ),
    }
}

fn log_reachable_host_summary(quiet: bool, report: &nrev::model::HostScanReport) {
    if quiet {
        return;
    }

    let reachable = report
        .targets
        .iter()
        .filter(|target| target.reachable)
        .map(|target| target.target.address.to_string())
        .collect::<Vec<_>>();
    progress(
        ProgressMode::Auto,
        quiet,
        &format!(
            "Reachable hosts: {} [{}]",
            reachable.len(),
            reachable.join(", ")
        ),
    );
}

fn log_open_port_summary(quiet: bool, report: &nrev::model::ScanReport) {
    if quiet {
        return;
    }

    for target in &report.targets {
        let open_ports = target
            .endpoints
            .values()
            .filter(|endpoint| endpoint.state == EndpointState::Open)
            .map(|endpoint| endpoint.port.to_string())
            .collect::<Vec<_>>();
        if open_ports.is_empty() {
            continue;
        }
        progress(
            ProgressMode::Auto,
            quiet,
            &format!(
                "{}: Open ports: [{}]",
                target.target.address,
                open_ports.join(", ")
            ),
        );
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    format!("{duration:?}")
}

fn scan_arg_sources(matches: Option<&clap::ArgMatches>) -> ScanArgSources {
    let Some(matches) = matches else {
        return ScanArgSources::default();
    };

    let is_cli = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);
    ScanArgSources {
        ports: is_cli("ports"),
        transport: is_cli("transport"),
        concurrency: is_cli("concurrency"),
        all_states: is_cli("all_states"),
        quiet: is_cli("quiet"),
        progress: is_cli("progress"),
        interface: is_cli("interface"),
        connect_timeout_ms: is_cli("connect_timeout_ms"),
        probe_timeout_ms: is_cli("probe_timeout_ms"),
        http_body_preview_bytes: is_cli("http_body_preview_bytes"),
        retries: is_cli("retries"),
        profile: is_cli("profile"),
        data: is_cli("data"),
        recipe: is_cli("recipe"),
        probes: is_cli("probes"),
        no_builtin_probes: is_cli("no_builtin_probes"),
        format: is_cli("format"),
        output: is_cli("output"),
    }
}
