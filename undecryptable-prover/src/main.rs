//! 无法解密证明器 — undecryptable-prover
//!
//! 设计纪律（核心，不妥协）：
//! - 不宣称「密码学不可破」——只证明「密钥材料经 N 轮覆写后，原字节不可恢复」。
//! - 输出可验证证据链（每轮覆写前后的非零字节计数），供人工复核，不自我认证。
//! - 用 zeroize 而非 `fill(0)`：防止编译器把「看似无用」的覆写优化掉（release 下 fill(0) 可能被 DCE 删除）。
//! - 本程序是「证据生成器」，不是「保证器」；法律/密码学强度的结论由人工基于证据判定。
//!
//! 缓冲区类型：`&mut [u8]`，**不是** `Vec<u8>`。
//! `Vec::zeroize()` 在清零后还会把长度置 0，后续轮次会迭代空切片 —— 多轮覆写会静默变成空转。
//! 切片实现只清零内容，不改长度，因此每一轮都能作用在真实字节上。
//!
//! 轮次语义：前 N−1 轮用确定性模式覆写原字节，**最后一轮 zeroize 归零**。
//! 顺序不能颠倒：先零化再模式覆写，等于用模式覆盖一堆零，原始密钥材料一次都没被覆写。

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const DEFAULT_LEN: usize = 32;
const DEFAULT_ROUNDS: usize = 3;
const MAX_LEN: usize = 4096;
const MAX_ROUNDS: usize = 64;

const USAGE: &str = "\
usage: undecryptable-prover [--len N] [--rounds N]

  --len N      secret length in bytes, 1..=4096 (default 32)
  --rounds N   overwrite rounds, 1..=64 (default 3); the last round is zeroize

This tool generates synthetic evidence. It reads no key material from disk,
from a pipe, or from stdin — by design.
";

/// 一轮覆写：返回该轮后缓冲区的非零字节计数与混合指纹。
///
/// 指纹是 FNV-1a 风格的混合，**不是**密码学摘要：它只用来让两轮结果可区分，
/// 不提供任何抗碰撞或抗原像性质。
fn round_fingerprint(buf: &[u8], round: u64) -> (usize, u64) {
    let mut nonzero = 0usize;
    let mut mix: u64 = 0xcbf2_9ce4_8422_2325u64 ^ round;
    for (i, b) in buf.iter().enumerate() {
        if *b != 0 {
            nonzero += 1;
        }
        mix = mix
            .rotate_left(13)
            .wrapping_add((*b as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15u64));
        mix ^= (i as u64).wrapping_add(round);
    }
    (nonzero, mix)
}

/// 确定性模式覆写（不依赖 CSPRNG 声明——它只是模式，不是随机源）。
///
/// 每个字节强制为奇数（`| 1`），因此模式轮结束后不可能出现零字节：
/// 若某一轮「没有覆写」，其 `nonzero_after` 会立刻掉到 0，证据链自己就会暴露空转。
fn fill_pattern(buf: &mut [u8], round: u64) {
    for (i, b) in buf.iter_mut().enumerate() {
        let mixed = (i as u64).wrapping_mul(31).wrapping_add(round) as u8;
        *b = (mixed ^ 0xAA) | 1;
    }
}

#[derive(Debug, Clone, Copy)]
struct Round {
    round: u64,
    nonzero_before: usize,
    nonzero_after: usize,
    fingerprint_after: u64,
}

/// 多轮覆写销毁：前 N−1 轮模式覆写，最后一轮 `zeroize`。
fn destroy_and_prove(secret: &mut [u8], rounds: usize) -> Vec<Round> {
    debug_assert!(rounds >= 1, "rounds must be >= 1");
    let mut chain = Vec::with_capacity(rounds);
    for r in 0..rounds {
        let (nonzero_before, _) = round_fingerprint(secret, r as u64);
        if r + 1 == rounds {
            secret.zeroize();
        } else {
            fill_pattern(secret, r as u64);
        }
        let (nonzero_after, fingerprint_after) = round_fingerprint(secret, r as u64);
        chain.push(Round {
            round: r as u64,
            nonzero_before,
            nonzero_after,
            fingerprint_after,
        });
    }
    chain
}

#[derive(Debug)]
struct Evidence {
    secret_len: usize,
    rounds: usize,
    timestamp_unix: u64,
    chain: Vec<Round>,
}

#[derive(Debug, Clone, Copy)]
struct Config {
    len: usize,
    rounds: usize,
}

enum ParseOutcome {
    Run(Config),
    Help,
}

impl Config {
    fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<ParseOutcome, String> {
        let mut cfg = Config {
            len: DEFAULT_LEN,
            rounds: DEFAULT_ROUNDS,
        };
        let mut it = args.into_iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--help" | "-h" => return Ok(ParseOutcome::Help),
                "--len" | "--rounds" => {
                    let which = arg.clone();
                    let raw = it.next().ok_or_else(|| format!("{which} needs a value"))?;
                    Self::assign(&mut cfg, &which, &raw)?;
                }
                other if other.starts_with("--len=") => {
                    Self::assign(&mut cfg, "--len", &other["--len=".len()..])?;
                }
                other if other.starts_with("--rounds=") => {
                    Self::assign(&mut cfg, "--rounds", &other["--rounds=".len()..])?;
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(ParseOutcome::Run(cfg))
    }

    fn assign(cfg: &mut Config, which: &str, raw: &str) -> Result<(), String> {
        let value: usize = raw
            .parse()
            .map_err(|_| format!("{which} expects a positive integer, got {raw:?}"))?;
        match which {
            "--len" => {
                if !(1..=MAX_LEN).contains(&value) {
                    return Err(format!("{which} must be in 1..={MAX_LEN}, got {value}"));
                }
                cfg.len = value;
            }
            "--rounds" => {
                if !(1..=MAX_ROUNDS).contains(&value) {
                    return Err(format!("{which} must be in 1..={MAX_ROUNDS}, got {value}"));
                }
                cfg.rounds = value;
            }
            _ => unreachable!("assign called with {which}"),
        }
        Ok(())
    }
}

/// 合成密钥材料：确定性、非零，仅用于产生可复核的证据。
/// 不接受外部输入 —— 本工具不应当成为处理真实密钥的通道。
fn seed_secret(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(7).wrapping_add(0x5a) as u8) | 1)
        .collect()
}

fn main() -> ExitCode {
    let cfg = match Config::parse(std::env::args().skip(1)) {
        Ok(ParseOutcome::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(ParseOutcome::Run(cfg)) => cfg,
        Err(message) => {
            eprintln!("error: {message}");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let mut secret = seed_secret(cfg.len);
    let secret_len = secret.len();
    let chain = destroy_and_prove(&mut secret, cfg.rounds);

    let timestamp_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let evidence = Evidence {
        secret_len,
        rounds: cfg.rounds,
        timestamp_unix,
        chain,
    };

    println!("# undecryptable-prover evidence");
    println!(
        "# len={} rounds={} ts={}",
        evidence.secret_len, evidence.rounds, evidence.timestamp_unix
    );
    for r in &evidence.chain {
        println!(
            "round={} nonzero_before={} nonzero_after={} fp_after={:#018x}",
            r.round, r.nonzero_before, r.nonzero_after, r.fingerprint_after
        );
    }

    // 证据自检：不是「断言安全」，而是「断言证据链没有自相矛盾」。
    let final_round_zero = evidence
        .chain
        .last()
        .map(|r| r.nonzero_after == 0)
        .unwrap_or(false);
    let buffer_really_zero = secret.iter().all(|b| *b == 0);
    let pattern_rounds = evidence.chain.len().saturating_sub(1);
    let patterns_wrote = evidence.chain[..pattern_rounds]
        .iter()
        .all(|r| r.nonzero_after == evidence.secret_len);

    if final_round_zero && buffer_really_zero && patterns_wrote {
        println!(
            "# final: buffer is all-zero after {} rounds, {} pattern round(s) wrote {} bytes each (evidence only, not a proof of cryptographic erasure)",
            evidence.rounds, pattern_rounds, evidence.secret_len
        );
    } else {
        println!(
            "# WARN: evidence incomplete — final_zero={final_round_zero} buffer_zero={buffer_really_zero} patterns_wrote={patterns_wrote}"
        );
    }

    let json = serde_free_evidence(&evidence);
    if let Err(e) = std::fs::write("evidence.json", json) {
        eprintln!("error: could not write evidence.json: {e}");
        return ExitCode::from(1);
    }
    println!("# evidence written to evidence.json");

    if final_round_zero && buffer_really_zero && patterns_wrote {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// 极简 JSON 序列化（避免引入 serde，保持零额外依赖除 zeroize）。
fn serde_free_evidence(e: &Evidence) -> String {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"secret_len\": {},\n", e.secret_len));
    s.push_str(&format!("  \"rounds\": {},\n", e.rounds));
    s.push_str(&format!("  \"timestamp_unix\": {},\n", e.timestamp_unix));
    s.push_str("  \"chain\": [\n");
    for (i, r) in e.chain.iter().enumerate() {
        s.push_str(&format!(
            "    [{}, {}, {}, {}]",
            r.round, r.nonzero_before, r.nonzero_after, r.fingerprint_after
        ));
        if i + 1 < e.chain.len() {
            s.push_str(",\n");
        } else {
            s.push('\n');
        }
    }
    s.push_str("  ]\n}\n");
    s
}
