const FILE_YEET_LOG_SUFFIX: &str = "file_yeet.log";

const MAX_LOG_FILE_COUNT: std::num::NonZeroUsize =
    std::num::NonZeroUsize::new(2).expect("MAX_LOG_FILE_COUNT must be a non-zero size");

/// Delete old log files in the application folder.
fn delete_old_logs(app_folder: &std::path::Path) {
    let entries = match std::fs::read_dir(app_folder) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Failed to read application folder: {e}");
            return;
        }
    };

    let mut log_files: Vec<_> = entries
        .into_iter()
        .filter_map(|entry| {
            match entry {
                Ok(entry) => {
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .ends_with(FILE_YEET_LOG_SUFFIX)
                    {
                        return Some(entry.path());
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read entry in application folder: {e}");
                }
            }
            None
        })
        .collect();

    if log_files.len() <= MAX_LOG_FILE_COUNT.get() {
        // If the number of log files is less than or equal to the maximum, no need to delete.
        return;
    }

    // Sort the log files by name so the most recent files are at the start of the list.
    log_files.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

    // Remove the oldest log files, keeping only the most recent ones.
    for path in &log_files[MAX_LOG_FILE_COUNT.get()..] {
        if let Err(e) = std::fs::remove_file(path) {
            eprintln!("Failed to remove log file: {e}");
        }
    }
}

/// Initialize logging. Attempt to log to a file in the application folder, or stdout if it fails.
/// Returns whether logging is using stdout.
pub fn init(args: &crate::Cli) -> bool {
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
                .max_log_files(MAX_LOG_FILE_COUNT.get())
                .build(&app_folder);

            if let Ok(file_appender) = file_appender {
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
                return false;
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

    // Logging with stdout.
    true
}
