//! Schema compatibility tests, executed by the pinned upstream Cedar CLI.
//!
//! These tests exercise fixture data only. They are not an OS policy gate and
//! do not qualify runtime confinement, grants, revocation, or journal behavior.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const CEDAR_VERSION: &str = "4.5.2";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cedar_binary() -> &'static OsString {
    static BINARY: OnceLock<OsString> = OnceLock::new();
    BINARY.get_or_init(|| {
        let binary = std::env::var_os("CEDAR_BIN").unwrap_or_else(|| "cedar".into());
        let output = Command::new(&binary)
            .arg("--version")
            .output()
            .expect("install the pinned Cedar CLI using scripts/bootstrap-tools.sh");
        assert!(
            output.status.success(),
            "Cedar --version failed: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            format!("cedar-policy-cli {CEDAR_VERSION}"),
            "the schema must be tested with the Cedar version in the pinned runtime"
        );
        binary
    })
}

fn cedar(args: &[&str]) -> Output {
    Command::new(cedar_binary())
        .args(args)
        .current_dir(root())
        .env("NO_COLOR", "1")
        .output()
        .expect("run Cedar CLI")
}

fn validate(policies: &str) -> Output {
    cedar(&[
        "validate",
        "--schema",
        "policy/schema.cedarschema",
        "--schema-format",
        "cedar",
        "--policies",
        policies,
        "--deny-warnings",
    ])
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "symbi-os-policy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // Never reuse an existing path or follow a pre-existing symlink.
        fs::create_dir(&path).expect("create fresh fixture directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authorize(policies: &str, class: &str, location: &str) -> Output {
    let scratch = Scratch::new();
    let request = scratch.0.join("request.json");
    fs::write(
        &request,
        format!(
            r#"{{
                "principal": "Symbi::Principal::\"fixture-agent\"",
                "action": "Symbi::Action::\"model.invoke\"",
                "resource": "Symbi::Model::\"{location}\"",
                "context": {{"session_class": "{class}"}}
            }}"#
        ),
    )
    .expect("write request fixture");
    cedar(&[
        "authorize",
        "--schema",
        "policy/schema.cedarschema",
        "--schema-format",
        "cedar",
        "--policies",
        policies,
        "--entities",
        "policy/tests/fixtures/entities.json",
        "--request-json",
        request.to_str().expect("UTF-8 fixture path"),
    ])
}

#[test]
fn schema_accepts_documented_model_attributes_and_session_context() {
    let output = validate("policy/tests/fixtures/model-policy.cedar");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn schema_rejects_undeclared_actions() {
    let output = validate("policy/tests/fixtures/unknown-action.cedar");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

#[test]
fn schema_rejects_mistyped_session_context() {
    let output = validate("policy/tests/fixtures/wrong-context.cedar");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

#[test]
fn base_policy_validates_without_warnings() {
    let output = validate("policy/base.cedar");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn base_policy_denies_every_session_class_and_model_location() {
    for class in ["public", "internal", "client-confidential"] {
        for location in ["local", "remote"] {
            let output = authorize("policy/base.cedar", class, location);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{class}/{location}: {output:?}"
            );
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "DENY");
        }
    }
}

#[test]
fn test_only_permit_proves_authorizer_is_not_always_denying() {
    let output = authorize(
        "policy/tests/fixtures/model-policy.cedar",
        "public",
        "local",
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ALLOW");
}
