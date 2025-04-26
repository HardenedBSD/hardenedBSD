#[cfg(windows)]
fn run() {
    use std::os::windows::io::RawHandle;
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) } as RawHandle;
    println!(
        "Size from terminal_size_using_handle(stdout): {:?}",
        terminal_size::terminal_size_using_handle(stdout)
    );

    let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) } as RawHandle;
    println!(
        "Size from terminal_size_using_handle(stderr): {:?}",
        terminal_size::terminal_size_using_handle(stderr)
    );

    let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) } as RawHandle;
    println!(
        "Size from terminal_size_using_handle(stdin):  {:?}",
        terminal_size::terminal_size_using_handle(stdin)
    );
}

#[cfg(not(windows))]
fn run() {
    use std::os::unix::io::AsRawFd;

    println!(
        "Size from terminal_size_using_fd(stdout):     {:?}",
        terminal_size::terminal_size_using_fd(std::io::stdout().as_raw_fd())
    );
    println!(
        "Size from terminal_size_using_fd(stderr):     {:?}",
        terminal_size::terminal_size_using_fd(std::io::stderr().as_raw_fd())
    );
    println!(
        "Size from terminal_size_using_fd(stdin):      {:?}",
        terminal_size::terminal_size_using_fd(std::io::stdin().as_raw_fd())
    );
}

fn main() {
    println!(
        "Size from terminal_size():                    {:?}",
        terminal_size::terminal_size()
    );

    run();
}
