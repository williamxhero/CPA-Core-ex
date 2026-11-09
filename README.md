<img align="right" src="./ex-badge.svg" alt="EX fork" width="76" />

# CLIProxyAPI-EX 主要能力

本页只列相对上游 router-for-me/CLIProxyAPI 的主要功能。上游已经提供代理、账号轮换和协议转换，但资源身份、额度证据和上游异常恢复仍容易在边界处丢失；本 fork 将这些能力放进 Core 的统一门禁和运行时。

- **资源目录与身份围栏**：上游缺少一套贯穿资源发现、凭证主体和实际请求的身份绑定。本 fork 建立资源目录、能力协商和身份围栏，让额度查询、刷新和请求都只能使用当前已登记的真实来源。对应 [issue #23](https://github.com/williamxhero/CPA-Core-ex/issues/23)。
- **Provider 推理门禁与成员密钥核对**：上游对“哪个成员、哪把密钥、哪个 Provider”之间的对应关系验证不足。本 fork 在运行前校验成员与密钥匹配，并以门禁和路由权威阻止未确认的推理来源进入请求链。
- **原生凭证额度与 Credits 观测**：上游额度接口难以稳定表达选定凭证的滚动/周期窗口。本 fork 提供选定凭证的额度查询，接入 Qwen Coding Plan 的真实月度窗口，并把 Codex Credits 随同额度观测返回，避免用缺失窗口伪造零值。
- **官方 OpenAI 路由与模型参数兼容**：上游官方 API provider 可能因错误 executor、过期资源身份和较低优先级而根本没有被请求；`gpt-6.1-sol` 也要求 `max_completion_tokens` 而不是 `max_tokens`。本 fork 将 `api-wxh` 纳入 OpenAI-compatible 路由、重建有效资源身份并修正最终参数。参数兼容对应 [issue #24](https://github.com/williamxhero/CPA-Core-ex/issues/24)，资源身份问题由本节第一条归档。
- **reasoning effort 可追溯用量**：上游用量记录无法区分“客户端未指定 effort”和“数据在翻译阶段丢失”。本 fork 用 `auto` 表示未指定、保留 `none` 和具体 effort，并防止上游响应覆盖客户端已选值。对应 [issue #25](https://github.com/williamxhero/CPA-Core-ex/issues/25)。
- **容量错误与未完成流的内部恢复**：上游遇到容量错误或流在传输中断时通常直接把失败交给客户端。本 fork 在 Core 内对可重试的容量失败和未完成流进行有界重试，同时保留顺序、取消和最终错误语义。对应 [issue #1](https://github.com/williamxhero/CPA-Core-ex/issues/1)、[#26](https://github.com/williamxhero/CPA-Core-ex/issues/26)、[#27](https://github.com/williamxhero/CPA-Core-ex/issues/27) 和 [#29](https://github.com/williamxhero/CPA-Core-ex/issues/29)。
- **额度耗尽前持续服务**：只要仍有可用 Provider 额度，Core 就会在容量错误、流中断或当前凭证不可用时继续切换候选凭证并重试；只有可用额度全部耗尽后才向客户端返回终止错误。对应 [issue #22](https://github.com/williamxhero/CPA-Core-ex/issues/22) 和 [issue #28](https://github.com/williamxhero/CPA-Core-ex/issues/28)。
- **用量双通道分发**：上游用量入队容易在订阅采集与 HTTP 轮询之间二选一。本 fork 同一条已提交记录同时通知订阅者并提供 HTTP 轮询，Keeper 等外部采集器可以并行工作而不会互相截断。
- **插件宿主兼容**：上游在 Windows 非 cgo 场景下对插件能力的声明不完整。本 fork 保持插件能力与运行时身份的一致，避免宿主因为构建模式误判而拒绝已验证的插件。

本页只说明 EX fork 的增量；Core 的协议、配置和部署文档仍以仓库正文为准。

> 完成 issue 归档更新时间：2026-11-09 08:34:40 SGT（UTC+08:00）。已列入上述条目的 issue 后续不再重复归档。
