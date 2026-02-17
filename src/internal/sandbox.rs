//! Landlock filesystem sandbox for restricting subprocess write access (Linux only).

use std::path::PathBuf;

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
};

/// Apply a Landlock sandbox that restricts filesystem writes to the given directories.
///
/// - Reads are allowed everywhere (`/`).
/// - Execute is allowed everywhere (needed for bash, git, etc.).
/// - Writes are allowed only in `writable_roots`, `/tmp`, and `~/.claude`.
///
/// Falls back gracefully if the kernel doesn't support Landlock.
pub fn apply_landlock_sandbox(
    writable_roots: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let abi = ABI::V3; // Linux 6.2+, includes Truncate

    let read_access = AccessFs::from_read(abi);
    let all_access = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default().handle_access(all_access)?.create()?;

    // Allow read access everywhere
    ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new("/")?, read_access))?;

    // Allow execute everywhere (needed for bash, git, etc.)
    ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new("/")?, AccessFs::Execute))?;

    // Allow write access to specified writable roots
    for root in writable_roots {
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(root)?, all_access))?;
    }

    // Allow writes to /tmp (Claude Code needs temp files)
    ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new("/tmp")?, all_access))?;

    // Allow writes to home config dirs (Claude Code session state)
    if let Ok(home) = std::env::var("HOME") {
        let claude_dir = PathBuf::from(&home).join(".claude");
        if claude_dir.exists() {
            ruleset =
                ruleset.add_rule(PathBeneath::new(PathFd::new(&claude_dir)?, all_access))?;
        }
    }

    let status = ruleset.restrict_self()?;
    if status.ruleset == RulesetStatus::NotEnforced {
        eprintln!("Warning: Landlock sandbox not enforced (kernel may not support it)");
    }

    Ok(())
}
