//! 无法解密证明器 — undecryptable-prover
//!
//! 设计纪律（核心，不妥协）：
//! - 不宣称「密码学不可破」——只证明「密钥材料经 N 轮确定性覆写后，原字节不可恢复」。
//! - 输出可验证证据链（每轮覆写前后的熵/零计数），供人工复核，不自我认证。
//! - 用 zeroize 而非 `fill(0)`：防止编译器把「看似无用」的覆写优化掉（release 下 fill(0) 可能被 DCE 删除）。
//! - 本程序是「证据生成器」，不是「保证器」；法律/密码学强度的结论由人工基于证据判定。

use zeroize::Zeroize;
use std::time::{SystemTime, UNIX_EPOCH};

/// 一轮覆写：用确定性模式覆盖，返回该轮后缓冲区的非零字节计数与 SHA-256 风格混合指纹。
/// 真实实现用标准 digest；此处用简化混合避免引入额外 crate（保持零依赖除 zeroize）。
fn round_fingerprint(buf: &[u8], round: u64) -> (usize, u64) {
    let mut nonzero = 0usize;
    let mut mix: u64 = 0xcbf2_9ce4_8422_2325u64 ^ round;
    for (i, b) in buf.iter().enumerate() {
        if *b != 0 {
            nonzero += 1;
        }
        mix = mix.rotate_left(13).wrapping_add((*b as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15u64));
        mix ^= (i as u64).wrapping_add(round);
    }
    (nonzero, mix)
}

/// 多轮覆写销毁：第 0 轮用全 0（验证 zeroize），后续轮用确定性模式。
/// 返回证据链：每轮的 (round, nonzero_before, nonzero_after, fingerprint_after)。
fn destroy_and_prove(secret: &mut Vec<u8>, rounds: usize) -> Vec<(u64, usize, usize, u64)> {
    let mut chain = Vec::with_capacity(rounds);
    for r in 0..rounds {
        let (nz_before, _fp_before) = round_fingerprint(secret, r as u64);
        match r {
            0 => secret.zeroize(), // 首轮：确定性全 0（zeroize 防优化）
            _ => {
                // 确定性伪随机覆写（不依赖 CSPRNG 声明——只是模式）
                for (i, b) in secret.iter_mut().enumerate() {
                    *b = ((i as u8).wrapping_mul(31).wrapping_add(r as u8)) ^ 0xAA;
                }
            }
        }
        let (nz_after, fp_after) = round_fingerprint(secret, r as u64);
        chain.push((r as u64, nz_before, nz_after, fp_after));
    }
    chain
}

/// 证据链结构（可序列化供人工复核 / 后续 Lean 导入）。
#[derive(Debug)]
struct Evidence {
    secret_len: usize,
    rounds: usize,
    timestamp_unix: u64,
    chain: Vec<(u64, usize, usize, u64)>,
}

fn main() {
    // 示例：一段「密钥材料」（实际使用时由调用方注入真实 secret，用完即 destroy）
    let mut secret: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(0x5a)).collect();

    let rounds = 3;
    let chain = destroy_and_prove(&mut secret, rounds);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let evidence = Evidence {
        secret_len: 32,
        rounds,
        timestamp_unix: timestamp,
        chain,
    };

    // 打印证据链（人类可读，不自我认证）
    println!("# undecryptable-prover evidence");
    println!("# len={} rounds={} ts={}", evidence.secret_len, evidence.rounds, evidence.timestamp_unix);
    for (r, nz_b, nz_a, fp) in &evidence.chain {
        println!("round={} nonzero_before={} nonzero_after={} fp_after={:#018x}", r, nz_b, nz_a, fp);
    }

    // 最终断言（仅陈述事实，不宣称密码学保证）：
    let last_after = evidence.chain.last().map(|c| c.2).unwrap_or(0);
    if last_after == 0 {
        println!("# final: buffer is all-zero after {} rounds (evidence only, not a proof of cryptographic erasure)", rounds);
    } else {
        println!("# WARN: final buffer nonzero={} — overwrite incomplete", last_after);
    }

    // 落盘证据（供 Lean 模板导入 / 人工复核）
    let json = serde_free_evidence(&evidence);
    std::fs::write("evidence.json", json).expect("write evidence failed");
    println!("# evidence written to evidence.json");
}

/// 极简 JSON 序列化（避免引入 serde，保持零额外依赖除 zeroize）。
fn serde_free_evidence(e: &Evidence) -> String {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"secret_len\": {},\n", e.secret_len));
    s.push_str(&format!("  \"rounds\": {},\n", e.rounds));
    s.push_str(&format!("  \"timestamp_unix\": {},\n", e.timestamp_unix));
    s.push_str("  \"chain\": [\n");
    for (i, (r, nz_b, nz_a, fp)) in e.chain.iter().enumerate() {
        s.push_str(&format!("    [{}, {}, {}, {}]", r, nz_b, nz_a, fp));
        if i + 1 < e.chain.len() {
            s.push_str(",\n");
        } else {
            s.push_str("\n");
        }
    }
    s.push_str("  ]\n}\n");
    s
}
