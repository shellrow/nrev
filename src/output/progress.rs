use indicatif::{ProgressState, ProgressStyle};

/// Get a progress bar style with a custom elapsed time formatter.
pub fn get_progress_style() -> ProgressStyle {
    let tpl = "{spinner:.green} {msg} [{elapsed_precise_subsec}] [{bar:40.cyan/blue}] {pos}/{len}";
    match ProgressStyle::default_bar().template(tpl) {
        Ok(style) => style,
        Err(_) => ProgressStyle::default_bar(),
    }
    .with_key("elapsed_precise_subsec", elapsed_precise_subsec)
    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"])
    .progress_chars("#>-")
}

/// Custom formatter for elapsed time with millisecond precision.
fn elapsed_precise_subsec(state: &ProgressState, writer: &mut dyn std::fmt::Write) {
    let elapsed = state.elapsed();
    let secs = elapsed.as_secs();
    let sub_ms = elapsed.subsec_millis();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    // HH:MM:SS.mmm
    let _ = write!(writer, "{:02}:{:02}:{:02}.{:03}", hours, mins, s, sub_ms);
}
