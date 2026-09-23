# 浏览器验签 bundle（`verify.iife.js`）

本文件是 `src/tsr.ts`（RFC 3161 TSR 验签）的**浏览器端口**，经 esbuild 打包为单文件 IIFE，
全局暴露 `window.CryptoTimeLedgerVerify.verifyTsrBytes(derBytes, digestHex, pinnedPem)`。

**为什么是单文件 bundle：** pkijs + asn1js 必须共享同一个实例。若用 CDN 分别 import（如
jsDelivr `+esm`），asn1js 会被内联/重写成第二个实例，pkijs 的 `compareSchema`/`instanceof`
跨实例静默失败（验签恒 false）。打包成单文件是唯一可靠姿势。

## 重新生成

```bash
cd crypto-time-ledger
npx esbuild src/browser-entry.ts \
  --bundle --format=iife --global-name=CryptoTimeLedgerVerify \
  --platform=browser --target=es2022 \
  --outfile=www/verify.iife.js
```

或直接跑 `node scripts/bundle-browser.cjs`（脚本把输出写到 `dist/`，再复制 `www/`）。

- **依赖**：esbuild（构建期），pkijs + asn1js（运行时，被打进 bundle）。esbuild 非
  `package.json` 依赖，用 `npx esbuild` 临时拉取（当前版本 0.28.2）。
- **升级 pkijs 后**：重跑上述命令重新打包，替换 `www/verify.iife.js`，并重跑
  `node scripts/smoke-e2e-fetch.mjs` 确认 4 块链仍全 PASS。

## 分发（MIME 关键）

- 本文件通过 **jsDelivr** 引用：`https://cdn.jsdelivr.net/gh/Lennonhaha/fibemate-tools@main/crypto-time-ledger/www/verify.iife.js`
  （jsDelivr 对 `.js` 返回 `application/javascript`，可作 `<script>` 引用）。
- **不可**用 raw.githubusercontent 引 `.js`：raw 返回 `text/plain` + `nosniff`，浏览器拒执行。
- 数据文件（`chain.json` / `.tsr` / `pinned-certs.pem`）走 raw fetch bytes，不受 MIME 限制。

## 验签契约（与 `src/tsr.ts` 完全一致）

1. 空 pin 集 fail-closed（返回 false）。
2. pin 白名单按 signer 证书 SPKI DER 比对（PKI-1）。
3. 显式 `messageImprint` 比对（`SignedData.verify()` 不做此语义检查）。
4. `eContentType` 临时覆盖为 `id-data`（跳过 pkijs「需原始数据」分支）。

## 开发期 PoC（未进 git）

仓库根还有 `crypto-time-ledger/poc/`（本地开发期浏览器 PoC，含 `poc.html` + `serve.cjs` +
`dist/` 重复 bundle），**未提交进 git**——正式交付物是上面的 `www/verify.iife.js`。重建方式：
`node scripts/bundle-browser.cjs` 生成 `dist/`，`poc/serve.cjs` 起本地 HTTP 供浏览器验证。
