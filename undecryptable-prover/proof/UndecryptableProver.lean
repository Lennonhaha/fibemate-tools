/- 无法解密证明器 — Lean4 证明骨架
   对应 Rust 实现：undecryptable-prover/src/main.rs（证据生成器）

   状态（诚实标注，勿删）：
   - 主定理结论**不是** `True`，也不含 `sorry`（sorry_count = 0）。
   - 唯一未证明处是 axiom `overwrite_erases`（威胁模型假设），axiom_count = 1。
     文件末尾的 `#print axioms` 会在每次编译时打印依赖，供人审计 ——
     不要删那一行，它就是这条假设的收据。
   - `NonRecoverable` 故意声明为 `opaque`：无法被展开成 `True`，
     所以不能靠「定义时偷偷放水」让定理恒真。
   - 前提与 Rust 证据链对齐：`rounds > 0`、`ev.length = rounds`、**末轮**为零。
     注意不是「每轮都为零」—— 模式轮本来就非零，写成每轮为零会让正确的
     实现在形式上变成反例。

   证据链映射：`evidence.json` 的 `chain` 每行是位置数组
     [round, nonzeroBefore, nonzeroAfter, fingerprintAfter]
   机器检查的导入器尚未实现（见 README「已知缺口」），此处只约定形状。

   术语边界：本文件证明的是「给定这些前提，非恢复性成立」。
   非恢复性本身来自 axiom，不是本文件证出来的 —— 这正是它必须显式登记的原因。
-/

/-- 证据链中的一轮覆写记录。 -/
structure RoundEvidence where
  round : Nat
  nonzeroBefore : Nat
  nonzeroAfter : Nat
  fingerprintAfter : Nat
deriving Repr, DecidableEq

/-- 「最后一轮结束后缓冲区为零」。空链不满足（没有末轮就谈不上归零）。 -/
def FinalRoundZero (ev : List RoundEvidence) : Prop :=
  match ev.getLast? with
  | some last => last.nonzeroAfter = 0
  | none => False

/-- 「原始字节不可恢复」。故意 `opaque`：其语义取决于存储介质威胁模型
    （例如「覆写后原扇区不可读」），本文件不定义它，也不允许它被展开成恒真。 -/
opaque NonRecoverable : List RoundEvidence → Prop

/-- 威胁模型假设（唯一未证明处，显式登记为 axiom 而非 theorem）。

    这不是「已经证明的东西」，而是「若要结论成立，必须成立的前提」。
    任何评审者都可以通过 `#print axioms undecryptable_after_N_rounds` 看到它。 -/
axiom overwrite_erases :
  ∀ (ev : List RoundEvidence) (rounds : Nat),
    0 < rounds →
    ev.length = rounds →
    FinalRoundZero ev →
    NonRecoverable ev

/-- 主定理：N 轮覆写、N > 0、末轮为零 ⇒ 原字节不可恢复（在上述假设下）。 -/
theorem undecryptable_after_N_rounds
    (ev : List RoundEvidence) (rounds : Nat)
    (h_pos : 0 < rounds)
    (h_len : ev.length = rounds)
    (h_final : FinalRoundZero ev) :
    NonRecoverable ev :=
  overwrite_erases ev rounds h_pos h_len h_final

/-! ## 具体见证

下面的链来自 Rust 实测（`--len 32 --rounds 3`）：
第 0、1 轮模式覆写（非零 → 非零），第 2 轮 zeroize（非零 → 0）。 -/

def observedChain : List RoundEvidence :=
  [ ⟨0, 32, 32, 0xd84ce17ea6a0f6cd⟩
  , ⟨1, 32, 32, 0x712d1a2a3e0c5fb2⟩
  , ⟨2, 32, 0, 0x84322125f7fe5d21⟩
  ]

/-- 前提不是空的：真实证据链能满足 `FinalRoundZero`。 -/
example : FinalRoundZero observedChain := by
  simp [FinalRoundZero, observedChain]

/-- 且长度前提确实成立。 -/
example : observedChain.length = 3 := rfl

/-- 反例：末轮非零时前提不成立 —— 说明该谓词有判别力，不是恒真。 -/
example : ¬ FinalRoundZero [⟨0, 32, 32, 0⟩] := by
  simp [FinalRoundZero]

-- 审计出口：每次编译都会打印主定理依赖的假设。
#print axioms undecryptable_after_N_rounds
