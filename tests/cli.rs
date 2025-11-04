use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};

mod test {

    use super::*;
    #[test]
    fn cli_lists_rules_pretty() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["rules", "list", "--format", "pretty", "--no-update-check"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("Pattern")));
    }
    #[test]
    fn cli_lists_rules_json() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["rules", "list", "--format", "json", "--no-update-check"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("pattern")));
    }

    #[test]
    fn cli_version_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("--version")
            .assert()
            .success()
            .stdout(contains(env!("CARGO_PKG_VERSION")));
    }
}
