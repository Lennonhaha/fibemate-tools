# cbom-tools

**Crypto Bill of Materials — scan, diff, report**

CBOM 工具链：识别密码学原语调用、生成/对比 CBOM 清单、生成迁移影响报告。

## 标准

本工具使用 **CycloneDX 1.6 CBOM 格式**（[规范](https://cyclonedx.org/specification/overview/)），由 OWASP 维护，Apache 2.0 许可证。

## 用法

```bash
# 默认：对比当前目录下的两份 CBOM JSON
node cbom-diff.js <old-cbom.json> <new-cbom.json>

# Git 模式：从 git 仓库指定 commit 读取 CBOM
node cbom-diff.js --git <old-hash> <new-hash>

# 输出 JSON 格式
node cbom-diff.js --json
```

## 免责声明

本工具**不实现**密码算法，**不提供**密码运算服务，**不构成**合规认证。所有密码学相关信息来源于 CycloneDX SBOM 标准和公开算法参数。

## License

Apache-2.0 © 2026 刘天赫