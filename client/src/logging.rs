const FILE_YEET_LOG_SUFFIX: &str = "file_yeet.log";

/// Delete old log files in the application folder.
fn delete_old_logs(app_folder: &std::path::Path) {
    match std::fs::read_dir(app_folder) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        if entry
                            .file_name()
                            .to_string_lossy()
                            .ends_with(FILE_YEET_LOG_SUFFIX)
                        {
                            if let Err(e) = std::fs::remove_file(entry.path()) {
                                eprintln!("Failed to remove log file: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to read entry in application folder: {e}");
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read application folder: {e}");
        }
    }
}

/// Initialize logging. Attempt to log to a file in the application folder, or stdout if it fails.
pub fn init(args: &crate::Cli) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    /// Generic function to create a tracing subscriber with a layer and filter.
    fn create<L>(
        subscriber: tracing_subscriber::Registry,
        layer: L,
        filter: tracing_subscriber::filter::Targets,
    ) where
        L: tracing_subscriber::layer::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
    {
        use tracing_subscriber::prelude::*;
        subscriber.with(layer).with(filter).init();
    }

    // Choose filters to apply to tracing statements to log.
    let filter = if cfg!(debug_assertions) || args.verbose {
        tracing_subscriber::filter::Targets::new()
            .with_target(crate::core::APP_TITLE, tracing::Level::DEBUG)
            .with_target("crab_nat", tracing::Level::DEBUG)
    } else {
        tracing_subscriber::filter::Targets::new()
            .with_target(crate::core::APP_TITLE, tracing::Level::INFO)
            .with_target("crab_nat", tracing::Level::INFO)
    };
    let subscriber = tracing_subscriber::registry();

    if !args.log_to_stdout {
        if let Some(app_folder) = crate::settings::app_folder() {
            // Delete previous log files if they exist.
            delete_old_logs(&app_folder);

            // If logging to a file, disable logging with ANSI coloring.
            let layer = tracing_subscriber::fmt::layer().with_ansi(false);

            // Log to a file in the application folder.
            let file_appender = tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_suffix(FILE_YEET_LOG_SUFFIX)
                .max_log_files(2)
                .build(&app_folder);

            if let Ok(file_appender) = file_appender {
                let (file_appender, guard) = tracing_appender::non_blocking(file_appender);

                if args.verbose {
                    create(
                        subscriber,
                        layer.pretty().with_writer(file_appender),
                        filter,
                    );
                } else {
                    create(
                        subscriber,
                        layer.compact().with_writer(file_appender),
                        filter,
                    );
                }

                // Initialization of logging to disk was successful
                return Some(guard);
            }

            eprintln!("Failed to create a log file in the application folder");
        } else {
            eprintln!("Failed to find an application folder for logging");
        }
        eprintln!("Fallback to stdout logging");
    }

    // Default stdout logging.
    let layer = tracing_subscriber::fmt::layer();
    if args.verbose {
        create(subscriber, layer.pretty(), filter);
    } else {
        create(subscriber, layer.compact(), filter);
    }

    None
}
