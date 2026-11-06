## 本 fork 的功能

相对上游 `router-for-me/CLIProxyAPI`，这条主干增加：

- 资源目录、身份围栏，以及选定凭证的额度查询。
- Qwen Coding Plan CLI 额度；缓存里只有一个真实月度窗口时，按这一个窗口接受。
- 提供商推理门禁，以及按成员核对密钥。
- 上游容量错误和未完成的流，先在 CPA 内重试。
- Codex Credits 随额度观测一起带出。
- Windows 上不启用 cgo 时，仍声明可以加载插件。
- 用量入队时同时发给订阅者和 HTTP 轮询。
