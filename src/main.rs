use check_elevation::is_elevated;
use std::process::Command;
use std::{str, thread};
use regex::Regex;
use std::env;
use std::time::Duration;

fn main() {
	let args: Vec<_> = env::args().collect();
	let mut dry_run = if args.len() >= 2 && args[1].eq("-n") {
		true
	} else {
		false
	};

	if !is_elevated().unwrap() {
		println!("Not elevated, using dry run");
		dry_run = true;
	}
	let user_listing = get_non_current_users();

	if user_listing.is_empty() {
		println!("No users to log out")

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

fn log_user_off(id: i32) {
	Command::new("logoff")
		.arg(id.to_string())
		.spawn()
		.expect("Could not log user off");
}

fn get_non_current_users() -> Vec<(String, i32)> {
	let process_result = Command::new("query")
		.arg("session")
		.output()
		.expect("failed to execute process");

	let other_user_sessions_reg = Regex::new(r"(?m)^[^>].*?((\S+)\s+(\d+)\s+)").unwrap();
	let cmd_output = str::from_utf8(&process_result.stdout).unwrap();

	let user_listing = other_user_sessions_reg.captures_iter(&cmd_output)
		.map(|m| {
			return (m.get(2).unwrap().as_str().to_string(), m.get(3).unwrap().as_str().parse::<i32>().unwrap());
		}).filter(|s| s.1 != 0)
		.collect::<Vec<(String, i32)>>();

	user_listing
}