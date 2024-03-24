use windows::Win32::{self, System::Console};

/// A helper for freeing the console if it was allocated by this process.
/// In practice, it helps avoid viewing a console window when run as a GUI application.
pub fn free_allocated_console() {
    // Get the console window handle.
    let console_window = unsafe { Console::GetConsoleWindow() };

    // Get the process ID of the console window.
    let mut console_process = 0;
    unsafe {
        Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(
            console_window,
            Some(&mut console_process),
        )
    };

    // Launched without a console if the current process is the owner of the provided console window.
    if unsafe { Win32::System::Threading::GetCurrentProcessId() == console_process } {
        // Free the allocated console window.
        unsafe { Console::FreeConsole().expect("Failed to free allocated console") };
    }
}
