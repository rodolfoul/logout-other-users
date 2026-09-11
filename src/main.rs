use check_elevation::is_elevated;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;
use std::{env, process, thread};
use windows::Win32::Foundation::{HANDLE, WAIT_FAILED};
use windows::Win32::System::Console::{AttachConsole, FreeConsole};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSLogoffSession, WTSQuerySessionInformationW, WTSUserName,
};
use windows::Win32::System::Threading::{INFINITE, WaitForSingleObject};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::core::{PCWSTR, w};

const ELEVATED_HELPER_ARGUMENT: &str = "--elevated-helper";

fn main() {
    let args: Vec<_> = env::args().collect();
    let dry_run = args.iter().any(|argument| argument == "-n");
    let parent_process_id = elevated_helper_parent_process_id(&args);

    if let Some(parent_process_id) = parent_process_id {
        attach_to_parent_console(parent_process_id);
    }

    let user_listing = match get_non_current_users() {
        Ok(user_listing) => user_listing,
        Err(error) => {
            eprintln!("Unable to check logged-in users: {error}");
            if parent_process_id.is_none() {
                exit_after_delay();
            }
            return;
        }
    };

    if parent_process_id.is_some() {
        log_out_users_from_elevated_helper(&user_listing);
        return;
    }

    if user_listing.is_empty() {
        println!("No users to log out");
    } else {
        print_users(&user_listing);
        process_user_sessions(&user_listing, dry_run);
    }
    exit_after_delay();
}

fn exit_after_delay() {
    println!("Exiting...");
    thread::sleep(Duration::from_millis(4000));
}

fn elevated_helper_parent_process_id(args: &[String]) -> Option<u32> {
    let argument_index = args
        .iter()
        .position(|argument| argument == ELEVATED_HELPER_ARGUMENT)?;
    args.get(argument_index + 1)?.parse().ok()
}

fn attach_to_parent_console(parent_process_id: u32) {
    unsafe {
        let _ = FreeConsole();
        let _ = AttachConsole(parent_process_id);
    }
}

fn print_users(user_listing: &[(String, u32)]) {
    println!("Found the following logged-in users:");
    for (user_name, session_id) in user_listing {
        println!("id:{} - {}", session_id, user_name);
    }
}

fn process_user_sessions(user_listing: &[(String, u32)], dry_run: bool) {
    if dry_run {
        println!("Dry run: no users will be logged out");
        return;
    }

    if !is_elevated().unwrap_or(false) {
        request_elevated_logout_and_wait();
        return;
    }

    for (_, session_id) in user_listing {
        log_user_off(*session_id);
    }
}

fn log_out_users_from_elevated_helper(user_listing: &[(String, u32)]) {
    if !is_elevated().unwrap_or(false) {
        eprintln!("Administrator permission was not granted; no users were logged out");
        return;
    }

    for (_, session_id) in user_listing {
        log_user_off(*session_id);
    }
}

fn request_elevated_logout_and_wait() {
    let executable_path = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Unable to locate this executable: {error}");
            return;
        }
    };
    let executable_path = executable_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let parameters = format!("{ELEVATED_HELPER_ARGUMENT} {}", process::id())
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();

    let _ = io::stdout().flush();

    let mut execute_info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(executable_path.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    if let Err(error) = unsafe { ShellExecuteExW(&mut execute_info) } {
        eprintln!("Permission was not granted; no users were logged out: {error}");
        return;
    }

    let process_handle = unsafe { OwnedHandle::from_raw_handle(execute_info.hProcess.0) };
    let wait_result =
        unsafe { WaitForSingleObject(HANDLE(process_handle.as_raw_handle()), INFINITE) };
    if wait_result == WAIT_FAILED {
        eprintln!("Unable to wait for the logout operation to finish");
    }
}

fn log_user_off(session_id: u32) {
    unsafe {
        if let Err(error) = WTSLogoffSession(None, session_id, false) {
            eprintln!("Unable to log out session {session_id}: {error}");
        }
    }
}

fn get_non_current_users() -> windows::core::Result<Vec<(String, u32)>> {
    unsafe {
        let current_session = current_session_id()?;
        let mut session_info_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count: u32 = 0;

        WTSEnumerateSessionsW(None, 0, 1, &mut session_info_ptr, &mut count)?;

        let sessions = std::slice::from_raw_parts(session_info_ptr, count as usize);
        let mut result = Vec::new();

        for session in sessions {
            let id = session.SessionId;
            if id == 0 || id == current_session {
                continue;
            }

            let mut name_ptr = windows::core::PWSTR::null();
            let mut bytes: u32 = 0;

            if WTSQuerySessionInformationW(None, id, WTSUserName, &mut name_ptr, &mut bytes).is_ok()
            {
                let username = name_ptr.to_string().unwrap_or_default();
                WTSFreeMemory(name_ptr.as_ptr().cast());
                if !username.is_empty() {
                    result.push((username, id));
                }
            }
        }

        WTSFreeMemory(session_info_ptr.cast());
        Ok(result)
    }
}

fn current_session_id() -> windows::core::Result<u32> {
    unsafe {
        let pid = process::id();
        let mut session_id = 0u32;
        ProcessIdToSessionId(pid, &mut session_id)?;
        Ok(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_parent_process_id_for_elevated_helper() {
        let args = vec![
            "logout-other-users.exe".to_owned(),
            ELEVATED_HELPER_ARGUMENT.to_owned(),
            "1234".to_owned(),
        ];

        assert_eq!(elevated_helper_parent_process_id(&args), Some(1234));
    }

    #[test]
    fn ignores_missing_or_invalid_parent_process_id() {
        let missing_id = vec![
            "logout-other-users.exe".to_owned(),
            ELEVATED_HELPER_ARGUMENT.to_owned(),
        ];
        let invalid_id = vec![
            "logout-other-users.exe".to_owned(),
            ELEVATED_HELPER_ARGUMENT.to_owned(),
            "invalid".to_owned(),
        ];

        assert_eq!(elevated_helper_parent_process_id(&missing_id), None);
        assert_eq!(elevated_helper_parent_process_id(&invalid_id), None);
    }
}