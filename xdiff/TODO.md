# TODO: CI 兼容

xdiff 当前的 xdiff.json 硬编码本地路径（D:/FIBEMATE/...），
在 CI 环境不可用。已被移出 fibemate 主仓 sentinel.yml。

未来需要：
- 支持相对路径（相对 xdiff 仓库根）
- 或 --impl-a / --impl-b 参数
- 或默认扫 ../fibemate/packages/pqc-kem/ 等

修完后可重新挂回 sentinel.yml，跑 cross-impl 差分（不是 test/run.js）。