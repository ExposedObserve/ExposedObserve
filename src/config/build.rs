// Copyright 2025 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{io::Result, process::Command, env};
use chrono::{DateTime, SecondsFormat, Utc};

fn get_git_info(args: &[&str], env_var: &str) -> String {
    if let Ok(val) = env::var(env_var) {
        return val;
    }

    let output = Command::new("git")
        .args(args)
        .output();

    match output {
        Ok(o) if o.status.success() => String::from_utf8(o.stdout).unwrap_or_default().trim().to_string(),
        _ => "unknown".to_string(),
    }
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    let version = get_git_info(&["describe", "--tags", "--abbrev=0", "--match", "v*"], "GIT_VERSION");
    println!("cargo:rustc-env=GIT_VERSION={}", version);
    let commit = get_git_info(&["rev-parse", "HEAD"], "GIT_COMMIT_HASH");
    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit);

    let now: DateTime<Utc> = Utc::now();
    let build_date = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    println!("cargo:rustc-env=GIT_BUILD_DATE={build_date}");

    Ok(())
}
