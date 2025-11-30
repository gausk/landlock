use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
    path_beneath_rules,
};

pub fn restrict_access() -> Result<(), RulesetError> {
    let abi = ABI::V1;

    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access to /usr, /etc and /dev.
        .add_rules(path_beneath_rules(
            &["/usr", "/etc", "/dev"],
            AccessFs::from_read(abi),
        ))?
        // Read-write access to /home and /tmp.
        .add_rules(path_beneath_rules(
            &["/home", "/tmp"],
            AccessFs::from_all(abi),
        ))?
        .restrict_self()?;

    match status.ruleset {
        // The FullyEnforced case must be tested by the developer.
        RulesetStatus::FullyEnforced => println!("Fully sandboxed."),
        RulesetStatus::PartiallyEnforced => println!("Partially sandboxed."),
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => println!("Not sandboxed! Please update your kernel."),
    }
    Ok(())
}

#[test]
fn test_restrict_access() {
    restrict_access().unwrap();

    let err = std::fs::read_dir("/var/log").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn test_without_restrict_access() {
    std::fs::read_dir("/var/log").unwrap();
}
