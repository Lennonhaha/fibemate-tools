# TODO: 可配置的实现根目录

xdiff 的 `xdiff.json` 里，实现路径是运行期输入（`${ROOT}` 展开），不进仓。
CI 上找不到配置文件时会退回 `src/config.js` 的内建默认表，而默认表里的相对路径
在 runner 上不存在，于是所有实现都是 unavailable。

未来需要：
- 支持相对路径（相对 xdiff 仓库根）
- 或 `--impl-a` / `--impl-b` 参数
- 或默认扫 `../fibemate/packages/pqc-kem/` 等

修完后可重新挂回主仓的 sentinel，跑 cross-impl 差分（不是 `test/run.js`）。

## 2026-10-11：CI 只能覆盖「降级路径」（治本待做）

- 现状：`xdiff.json` 未进仓 → CI 上 `findConfigFile` 找不到配置 → 退回 `src/config.js` 的 DEFAULTS
  内建实现表（相对仓根解析）→ runner 上不存在 → 所有实现 unavailable、liboqs disabled
  → engine 只产出 1 条 `[error] matrix`、0 个 case。
- 故 `test/run.js` 的 engine 冒烟改为「无 ready 实现时只断言 findings 非空」。
  ⚠️ 回归绿 ≠ xdiff 真差分被测过：CI 目前只覆盖「实现缺失时优雅降级」，不覆盖 cross-impl 差分。
- 治本方向（择一/组合）：① env 注入实现根目录（`config.js` 支持 `${ROOT}` 展开）；
  ② 提交 CI 专用配置，仅启用仓内可满足的实现（CI 里 `npm ci` 装 `@noble/post-quantum` 后指向 `node_modules`）。

## 硬编码本地路径：已清理（2026-11-23）

原本散落在下列位置的绝对路径，现已全部改为相对路径或环境变量，仓库内不再出现本机目录：

- `test/run.js` 的 KAT `.rsp` 路径 → 与实现路径同样按 `__dirname` 相对解析，另支持环境变量覆盖
- `src/impls/liboqs.js` 注释里的构建目录 → 改为不含路径的表述
- `README.md` 示例命令里的绝对路径 → 改为 `<liboqs>` 之类占位
