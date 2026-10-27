// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫 <research@fibemate.net>

//! Black-box characterisation tests for the evidence generator.
//!
//! These deliberately pin the behaviour that exists **today**, including the
//! known defects, so that the refactor in the next PR shows up as an explicit
//! diff instead of a silent change. Tests marked `#[ignore]` state what should
//! hold and fail against the current implementation; run them with:
//!
//! ```text
//! cargo test -- --ignored
//! ```
//!
//! The binary is exercised through `CARGO_BIN_EXE_*` with the working directory
//! set to a throw-away directory, because it writes `evidence.json` into the
//! current directory. No `serde` / `regex` dependency is added: the evidence
//! file is parsed by hand and a format change is meant to fail loudly here.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_undecryptable-prover");

/// Current hard-coded dimensions in `src/main.rs`.
const EXPECTED_SECRET_LEN: u64 = 32;
const EXPECTED_ROUNDS: u64 = 3;

type Row = (u64, u64, u64, u64);

struct Outcome {
    dir: PathBuf,
    stdout: String,
    code: Option<i32>,
}

impl Drop for Outcome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("udp-{}-{}-{}", tag, std::process::id(), nanos));
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn run(tag: &str, args: &[&str]) -> Outcome {
    let dir = scratch_dir(tag);
    let out = Command::new(BIN)
        .args(args)
        .current_dir(&dir)
        .output()
        .expect("spawn undecryptable-prover");
    Outcome {
        dir,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code(),
    }
}

fn evidence_path(out: &Outcome) -> PathBuf {
    out.dir.join("evidence.json")
}

fn evidence_text(out: &Outcome) -> String {
    let p = evidence_path(out);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Read `"key": <digits>` from the flat part of the evidence file.
fn scalar(json: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\":");
    let at = json
        .find(&needle)
        .unwrap_or_else(|| panic!("missing key {key}"));
    let rest = &json[at + needle.len()..];
    let digits: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("key {key} is not a number"))
}

/// Parse the `chain` array, which is serialised as rows of four integers.
fn rows(json: &str) -> Vec<Row> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in json.lines() {
        let line = line.trim();
        if line.starts_with("\"chain\"") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        let Some(body) = line.strip_prefix('[') else {
            continue;
        };
        let body = body.trim_end_matches(',').trim_end_matches(']');
        let nums: Vec<u64> = body
            .split(',')
            .map(|n| {
                n.trim()
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("bad chain row: {line}"))
            })
            .collect();
        assert_eq!(nums.len(), 4, "chain row must have four columns: {line}");
        out.push((nums[0], nums[1], nums[2], nums[3]));
    }
    out
}

fn normalised(json: &str) -> String {
    json.lines()
        .map(|l| {
            if l.trim_start().starts_with("\"timestamp_unix\"") {
                "\"timestamp_unix\": <t>,"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// --- characterisation: behaviour that exists today -------------------------

#[test]
fn writes_evidence_next_to_the_working_directory() {
    let out = run("writes", &[]);
    assert_eq!(
        out.code,
        Some(0),
        "expected success, stdout:\n{}",
        out.stdout
    );
    assert!(
        evidence_path(&out).is_file(),
        "evidence.json was not written to the working directory ({})",
        out.dir.display()
    );
}

#[test]
fn reports_the_hard_coded_dimensions() {
    let out = run("dims", &[]);
    let json = evidence_text(&out);
    assert_eq!(scalar(&json, "secret_len"), EXPECTED_SECRET_LEN);
    assert_eq!(scalar(&json, "rounds"), EXPECTED_ROUNDS);
    assert_eq!(rows(&json).len() as u64, EXPECTED_ROUNDS);
}

#[test]
fn final_round_zeroises_the_buffer() {
    let out = run("zero", &[]);
    let chain = rows(&evidence_text(&out));
    let (last_round, before, after, _) = *chain.last().expect("non-empty chain");
    assert_eq!(last_round, EXPECTED_ROUNDS - 1);
    assert_eq!(
        before, EXPECTED_SECRET_LEN,
        "the final round must start on real bytes"
    );
    assert_eq!(after, 0, "the last round must leave zero non-zero bytes");

    // Every earlier round must have left the buffer full and non-zero, otherwise
    // the final zero could be the result of doing nothing at all.
    for (round, _, after, _) in chain.iter().take(chain.len() - 1) {
        assert_eq!(
            *after, EXPECTED_SECRET_LEN,
            "pattern round {round} left {after} non-zero bytes instead of {EXPECTED_SECRET_LEN}"
        );
    }
}

#[test]
fn timestamp_is_close_to_now() {
    let out = run("time", &[]);
    let json = evidence_text(&out);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let ts = scalar(&json, "timestamp_unix");
    let delta = now.abs_diff(ts);
    assert!(
        delta < 600,
        "timestamp {ts} is {delta}s away from now ({now})"
    );
}

#[test]
fn stdout_does_not_claim_a_cryptographic_guarantee() {
    let out = run("claim", &[]);
    let lower = out.stdout.to_lowercase();
    assert!(
        lower.contains("evidence only, not a proof"),
        "the disclaimer is the point of this tool; stdout was:\n{}",
        out.stdout
    );
    for forbidden in [
        "is secure",
        "guarantees erasure",
        "cryptographically erased",
    ] {
        assert!(!lower.contains(forbidden), "stdout overclaims: {forbidden}");
    }
}

#[test]
fn repeated_runs_differ_only_in_the_timestamp() {
    let a = evidence_text(&run("rep-a", &[]));
    let b = evidence_text(&run("rep-b", &[]));
    assert_eq!(
        normalised(&a),
        normalised(&b),
        "evidence must be deterministic apart from the timestamp"
    );
}

#[test]
fn does_not_touch_the_source_tree() {
    let tracked = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence.json");
    let before = fs::metadata(&tracked).and_then(|m| m.modified()).ok();
    let _out = run("cwd", &[]);
    let after = fs::metadata(&tracked).and_then(|m| m.modified()).ok();
    assert_eq!(
        before, after,
        "the binary wrote into the crate directory instead of its cwd"
    );
}

// --- defect regression tests: these failed before the fix -------------------

/// A multi-round overwrite must actually write in rounds after the first one.
///
/// Before the fix: `Vec<u8>::zeroize()` truncated the vector to length 0, so
/// every round after the first iterated over an empty slice and wrote nothing,
/// while the program still printed "buffer is all-zero".
#[test]
fn rounds_after_the_first_touch_bytes() {
    let out = run("touch", &[]);
    let chain = rows(&evidence_text(&out));
    assert!(
        chain.iter().skip(1).any(|(_, _, after, _)| *after > 0),
        "no round after the first reported non-zero bytes; the overwrite is a no-op: {chain:?}"
    );
}

/// A multi-round overwrite must operate on the full buffer each round.
#[test]
fn buffer_keeps_its_length_across_rounds() {
    let out = run("len", &[]);
    let chain = rows(&evidence_text(&out));
    for (round, before, _, _) in chain.iter().skip(1) {
        assert_eq!(
            *before, EXPECTED_SECRET_LEN,
            "round {round} started with {before} bytes instead of {EXPECTED_SECRET_LEN}"
        );
    }
}

/// Invalid input must not be silently accepted.
#[test]
fn rejects_invalid_arguments() {
    for args in [
        vec!["--rounds", "abc"],
        vec!["--rounds", "0"],
        vec!["--rounds", "65"],
        vec!["--len", "0"],
        vec!["--len", "999999"],
        vec!["--len"],
        vec!["--bogus"],
    ] {
        let out = run("args", &args);
        assert_eq!(
            out.code,
            Some(2),
            "args {args:?} should exit 2, got {:?}",
            out.code
        );
        assert!(
            !evidence_path(&out).exists(),
            "args {args:?} must not write evidence"
        );
    }
}

#[test]
fn custom_length_and_rounds_are_honoured() {
    let out = run("custom", &["--len", "17", "--rounds", "4"]);
    assert_eq!(out.code, Some(0), "stdout:\n{}", out.stdout);
    let json = evidence_text(&out);
    assert_eq!(scalar(&json, "secret_len"), 17);
    assert_eq!(scalar(&json, "rounds"), 4);
    let chain = rows(&json);
    assert_eq!(chain.len(), 4);
    assert_eq!(chain[3].2, 0, "last round must zeroise");
    for (round, before, after, _) in &chain {
        assert!(
            *before <= 17 && *after <= 17,
            "round {round} counts exceed the buffer length"
        );
    }
    for (round, _, after, _) in chain.iter().take(3) {
        assert_eq!(*after, 17, "pattern round {round} should fill all 17 bytes");
    }
}

#[test]
fn single_round_is_a_pure_zeroise() {
    let out = run("single", &["--rounds", "1"]);
    assert_eq!(out.code, Some(0), "stdout:\n{}", out.stdout);
    let chain = rows(&evidence_text(&out));
    assert_eq!(chain.len(), 1);
    assert_eq!(
        chain[0].1, EXPECTED_SECRET_LEN,
        "the secret starts non-zero"
    );
    assert_eq!(chain[0].2, 0);
    assert!(
        out.stdout.contains("0 pattern round(s)"),
        "stdout should state that no pattern round ran:\n{}",
        out.stdout
    );
}
