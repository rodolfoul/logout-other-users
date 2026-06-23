use check_elevation::is_elevated;
use std::time::Duration;
use std::{env, thread};
use windows::Win32::System::RemoteDesktop::{
	ProcessIdToSessionId, WTSEnumerateSessionsW, WTSFreeMemory, WTSLogoffSession,
	WTSQuerySessionInformationW, WTSUserName, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

fn main() {
	let args: Vec<_> = env::args().collect();
	let mut dry_run = args.len() >= 2 && args[1] == "-n";

	if !is_elevated().unwrap() {
		println!("Not elevated, using dry run");
		dry_run = true;
	}

	let user_listing = get_non_current_users();

	if user_listing.is_empty() {
		println!("No users to log out");
	} else {
		println!("Logging out the following users:");
		for (user_name, id) in user_listing {
			println!("id:{} - {}", id, user_name);
			if !dry_run {
				log_user_off(id);
			}
		}
	}
	println!("Exiting...");
	thread::sleep(Duration::from_millis(4000));
}

fn log_user_off(session_id: u32) {
	unsafe {
		let _ = WTSLogoffSession(None, session_id, false);
	}
}

fn get_non_current_users() -> Vec<(String, u32)> {
	unsafe {
		let current_session = current_session_id();
		let mut session_info_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
		let mut count: u32 = 0;

		if WTSEnumerateSessionsW(None, 0, 1, &mut session_info_ptr, &mut count).is_err() {
			return Vec::new();
		}

		let sessions = std::slice::from_raw_parts(session_info_ptr, count as usize);
		let mut result = Vec::new();

		for session in sessions {
			let id = session.SessionId;
			if id == 0 || id == current_session {
				continue;
			}

			let mut name_ptr = windows::core::PWSTR::null();
			let mut bytes: u32 = 0;

			if WTSQuerySessionInformationW(None, id, WTSUserName, &mut name_ptr, &mut bytes).is_ok() {
				let username = name_ptr.to_string().unwrap_or_default();
				WTSFreeMemory(name_ptr.as_ptr().cast());
				if !username.is_empty() {
					result.push((username, id));
				}
			}
		}

		WTSFreeMemory(session_info_ptr.cast());
		result
	}
}

fn current_session_id() -> u32 {
	unsafe {
		let pid = GetCurrentProcessId();
		let mut session_id = 0u32;
		let _ = ProcessIdToSessionId(pid, &mut session_id);
		session_id
	}
}