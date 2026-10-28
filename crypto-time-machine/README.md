# crypto-time-machine

用 **git 真历史** 回答一个问题：某个密码学 API / 算法是哪个 commit 引入的、何时被改过、影响了哪些文件。

零第三方依赖（只用标准库 `subprocess` / `sqlite3` / `json`），只读仓库，不写任何源文件。

## 安装

```bash
pip install crypto-time-machine
```

## 用法

```bash
# 在任意 git 仓库里追踪一个符号，产出 timeline.db
crypto-time-machine --repo /path/to/repo --pattern ml_kem768

# 只看某个 commit 之后的影响面
crypto-time-machine --repo . --pattern ml_kem768 --query-after <sha>

# 用 -G（diff 命中）而不是 -S（内容变化）
crypto-time-machine --repo . --pattern kyber --mode -G

# 默认数据库是当前目录的 timeline.db，可显式指定
crypto-time-machine --repo . --pattern ml_kem768 --db /tmp/t.db
```

等价的模块入口：`python -m ctime --pattern ml_kem768`。

## 输出与退出码

- 成功：stdout 打印 `pattern=... mode=... events=N db=...`，退出码 **0**
- 不是 git 仓库 / git 执行失败：stderr 给出原因，退出码 **2**
- 模式匹配为空：**默认拒绝覆盖**已有时间轴并退出 **2**；确需写入空结果加 `--allow-empty`
- `--query-after` 给了不在时间轴里的 sha：退出 **2**（不静默返回全量）

## 边界（明确不做的事）

- **不判断安全性**：只报告「何时引入/变更/影响哪些文件」，不做漏洞判定
- **不做语义猜测**：所有结论来自 `git log -S/-G` 的真实输出，匹配为空就报空
- **不改仓库**：只读；数据库写在 `--db` 指定位置
- **不合并历史**：重命名 / 跨文件移动的追踪依赖 git 自身的 `--follow` 语义，超出范围时不猜测

## 许可

Apache-2.0
