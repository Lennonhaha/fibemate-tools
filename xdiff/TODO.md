# TODO: CI 兼容

xdiff 当前的 xdiff.json 硬编码本地路径（D:/FIBEMATE/...），
在 CI 环境不可用。已被移出 fibemate 主仓 sentinel.yml。

未来需要：
- 支持相对路径（相对 xdiff 仓库根）
- 或 --impl-a / --impl-b 参数
- 或默认扫 ../fibemate/packages/pqc-kem/ 等

修完后可重新挂回 sentinel.yml，跑 cross-impl 差分（不是 test/run.js）。s => (s.includes('\r\n') ? '\r\n' : '\n')## 2026-10-11：CI 只能覆盖「降级路径」（治本待做）s => (s.includes('\r\n') ? '\r\n' : '\n')s => (s.includes('\r\n') ? '\r\n' : '\n')- 现状：xdiff.json 未进仓 → CI 上 findConfigFile 找不到配置 → 退回 src/config.js 的 DEFAULTSs => (s.includes('\r\n') ? '\r\n' : '\n')  内建实现表（路径 ../../fibemate… 相对仓根解析）→ runner 上不存在 → cp/main/noble 全 unavailable、s => (s.includes('\r\n') ? '\r\n' : '\n')  liboqs disabled → engine 只产出 1 条 [error] matrix、0 个 case。s => (s.includes('\r\n') ? '\r\n' : '\n')- 故 test/run.js 的 engine 冒烟改为「无 ready 实现时只断言 findings 非空」。s => (s.includes('\r\n') ? '\r\n' : '\n')  ⚠️ 回归绿 ≠ xdiff 真差分被测过：CI 目前只覆盖「实现缺失时优雅降级」，不覆盖 cross-impl 差分。s => (s.includes('\r\n') ? '\r\n' : '\n')- 治本方向（择一/组合）：① env 注入实现根目录（config.js 支持 ${FIBEMATE} 展开）；s => (s.includes('\r\n') ? '\r\n' : '\n')  ② 提交 CI 专用配置，仅启用仓内可满足的实现（CI 里 npm ci 装 @noble/post-quantum 后指向 node_modules）。s => (s.includes('\r\n') ? '\r\n' : '\n')- 同族硬编码本地路径（一并治本，勿分散修）：s => (s.includes('\r\n') ? '\r\n' : '\n')  - test/run.js:228  D:/FIBEMATE/fibemate/packages/pqc-kem/test/kat/mlkem-768-KAT.rsp（有 existsSync 守卫 → CI 跳过）s => (s.includes('\r\n') ? '\r\n' : '\n')  - src/impls/liboqs.js:13（注释里的 D:\FIBEMATE\liboqs-build）s => (s.includes('\r\n') ? '\r\n' : '\n')  - README.md:61/67/68/111/112/133（示例命令里的 D:\FIBEMATE）s => (s.includes('\r\n') ? '\r\n' : '\n')