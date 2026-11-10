mod cli;
mod serve;

use anyhow::Result;

/// Print the `--help` text to stdout.
fn print_help() {
    println!("wavvon-hub {}\n", env!("CARGO_PKG_VERSION"));
    println!("USAGE:");
    println!("  wavvon-hub [SUBCOMMAND | OPTION]\n");
    println!("SUBCOMMANDS:");
    println!("  setup            Interactive install wizard: generates docker-compose.yml + .env");
    println!("  migrate          Apply DB migrations and exit");
    println!(
        "  backup [FILE]    Back up database + identity + uploads \
         (default: hub-backup-<ts>.tar.gz)"
    );
    println!("  restore FILE [--force]");
    println!("                   Restore a backup archive. Refuses a non-empty");
    println!("                   destination unless --force.");
    println!("  db move --to URL | --from URL [--force]");
    println!("                   Copy this hub's database to (or from) another");
    println!("                   PostgreSQL. Copies only: it does not switch");
    println!("                   modes, and leaves the source untouched.");
    println!("  rotate-key       Generate a new hub keypair and sign a rotation payload");
    println!(
        "                   --endorse-from OLD.json: have an old identity endorse the current one"
    );
    println!("  update [--check] Self-update binary from GitHub releases (Linux x86_64 only)");
    println!("  admin <cmd>      Admin CLI (stats|users|channels|tokens|backup|restore)\n");
    println!("OPTIONS:");
    println!("  -h, --help       Print this help message");
    println!("  -V, --version    Print version");
    println!("  --doctor         Pre-flight checks: bind ports, verify TLS files, check disk\n");
    println!("ENVIRONMENT VARIABLES:");

    let name_w = wavvon_hub::settings::ENV_VAR_HELP
        .iter()
        .map(|(n, _, _)| n.len())
        .max()
        .unwrap_or(20);
    let default_w = wavvon_hub::settings::ENV_VAR_HELP
        .iter()
        .map(|(_, d, _)| d.len())
        .max()
        .unwrap_or(10);

    println!(
        "  {:<name_w$}  {:<default_w$}  Purpose",
        "Variable", "Default"
    );
    println!(
        "  {:<name_w$}  {:<default_w$}  {}",
        "-".repeat(name_w),
        "-".repeat(default_w),
        "-".repeat(40)
    );
    for (name, default, purpose) in wavvon_hub::settings::ENV_VAR_HELP {
        println!("  {name:<name_w$}  {default:<default_w$}  {purpose}");
    }
    println!();
    println!("Configuration is also accepted from hub.toml in the working directory.");
    println!("Environment variables override hub.toml values.");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Fast-path CLI flags that don't need settings or logging.
    let args: Vec<String> = std::env::args().collect();
    let first_arg = args.get(1).map(|s| s.as_str());

    if matches!(first_arg, Some("-h") | Some("--help")) {
        print_help();
        return Ok(());
    }

    if matches!(first_arg, Some("-V") | Some("--version")) {
        println!("wavvon-hub {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if first_arg == Some("--doctor") {
        let ok = cli::doctor::run_doctor().await;
        std::process::exit(if ok { 0 } else { 1 });
    }

    // `setup` is a pure file-generation wizard: it needs none of the DB/TLS/
    // port config `settings::load()` would otherwise require, and is in fact
    // meant to be usable *before* any of that exists yet. Dispatched here,
    // fast-path, same as --help/--version/--doctor above.
    if first_arg == Some("setup") {
        let setup_args: Vec<String> = std::env::args().skip(2).collect();
        match wavvon_hub::setup::run(&setup_args) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    let settings = match wavvon_hub::settings::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    let json_logs = settings.log_format.to_lowercase() == "json";

    // Optional OpenTelemetry OTLP trace export.
    // Set WAVVON_OTLP_ENDPOINT or otlp_endpoint in hub.toml to any
    // OTLP-compatible collector (Grafana Tempo, Jaeger, Honeycomb, Datadog, etc.).
    // No-op when unset or empty.
    let otlp_provider = settings
        .otlp_endpoint
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|endpoint| {
            use opentelemetry_otlp::WithExportConfig;
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build()
                .ok()?;
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_service_name(env!("CARGO_PKG_NAME"))
                        .build(),
                )
                .build();
            opentelemetry::global::set_tracer_provider(provider.clone());
            Some(provider)
        });

    use tracing_subscriber::prelude::*;
    let otel_layer = otlp_provider.as_ref().map(|provider| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(provider.tracer(env!("CARGO_PKG_NAME")))
    });

    // Respect RUST_LOG; default to info. Without a filter the subscriber
    // logs TRACE from every dependency (tokio_tungstenite polls, sqlx
    // statements), which floods files/journald on any real deployment.
    let env_filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    if json_logs {
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_filter(env_filter()),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer().with_filter(env_filter()))
            .init();
    }

    tracing::info!("Configuration loaded");

    if otlp_provider.is_some() {
        tracing::info!("OpenTelemetry OTLP trace export enabled");
    }

    match std::env::args().nth(1).as_deref() {
        Some("migrate") => return cli::db::migrate().await,
        Some("backup") => return cli::db::backup_cmd().await,
        Some("restore") => return cli::db::restore_cmd().await,
        Some("db") if std::env::args().nth(2).as_deref() == Some("move") => {
            return cli::db::move_cmd().await
        }
        Some("rotate-key") => return cli::keys::rotate_key_cmd(),
        Some("update") => return cli::update::update_cmd().await,
        Some("admin") => return cli::admin::run().await,
        _ => {}
    }

    serve::run(settings, otlp_provider).await
}
