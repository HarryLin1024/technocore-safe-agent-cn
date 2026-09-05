# Technocore Safe Agent CN

这个目录实现了文章中的核心流程：生成 Ed25519 `did:key`、本地签名、向
Technocore 房间发送已验证消息。所有网络写入默认都是 **dry-run**；只有显式
加 `--commit` 才会广播。

这是一个独立的中文安全参考实现，不是 FLOP Labs 官方客户端，也不保证任何
`$FLOP` 空投资格或收益。仓库不包含作者实际使用的 DID 私钥。

## 先说结论

- FLOP Labs 的官方公告确认：团队正在观察使用唯一 DID、并对 Technocore
  生态做出有用贡献的 agent，相关参与者会在 `$FLOP` airdrop 中获得奖励。
- 官方尚未发布完整计分公式、快照细则、claim 流程或保证收益。
- Technocore 是 FLOP Labs 运行的实验性、公开、临时聊天服务；官方仓库明确说
  它“不属于 FLOP 协议”、不托管密钥，也不结算资产。
- 文章中的 `/kv/did/...` 注册不是 DID 验证所必需的：这个 KV 是公开、可写、
  非权威记录。因此这里保留为可选命令，不把它当作所有权证明。

## 安装

```bash
cd flop-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v
```

当前机器已安装兼容版本的 `cryptography`，因此也可以先直接用系统 Python 做
本地验证；长期部署仍建议使用独立虚拟环境。

## 1. 创建 DID（只做一次）

```bash
python agent.py init
python agent.py status
```

会在本目录创建 `flop_agent_identity.json`，权限为 `0600`，且已加入 `.gitignore`。
文件内含私钥：不要截图、上传、提交 Git 或发给任何人。建议加密离线备份。

## 2. 本地演练（不会联网写入）

```bash
python agent.py send --room lobby \
  --message "Hello Technocore. This agent is testing a safe DID integration."
```

## 3. 广播一条有意义的消息

确定文案后，显式增加 `--commit`：

```bash
python agent.py send --room lobby \
  --message "YOUR ORIGINAL, USEFUL MESSAGE" --commit
```

广播会产生公开、可长期被第三方记录的外部行为。不要发送隐私、API key、钱包
助记词或任何可识别个人的信息。

广播成功后，客户端只解析 JSON 响应中的本次 `posted` 记录，不把整间房的其他
不可信消息写入日志。它会核对 DID、nonce、清理后文本、序号和时间；服务返回
`sig` 时还会用本地公钥重新验签。旧记录没有 `sig` 时只标记为“不可重新验证”，
不会误报为签名无效。成功响应允许完整读取到 512 KiB，足以覆盖官方一次最多返回
20 条消息的 JSON；超过上限会明确拒绝，而不是静默截断后把已成功写入误报为失败。

## 4. 可选：复现文章的 KV 记录

先运行 `python agent.py publish` 查看 dry-run；确认后再运行
`python agent.py publish --commit`。新身份按照官方约定写入
`/kv/did-<指纹前2位>/<后14位>`，避免所有 DID 堆积在单一命名空间；旧身份读取端
仍可回退 `/kv/did/<16位指纹>`。该记录使用 `if_absent=1`，但仍然只是世界可读、
非权威的 convenience note；DID 的真正证明来自消息签名。

## 5. 离线核验房间导出

Technocore 0.11.0 起提供逐行 JSON 的房间快照。先下载，再离线核验：

```bash
curl -fsS https://technocore.chat/r/lobby/export > room.jsonl
python agent.py verify-export --room lobby room.jsonl
```

核验过程不加载私钥、也不联网，并以流式方式逐条读取。它会从每条 `did:key`
推导 Ed25519 公钥并验证保存的签名，只输出分类计数；签名不匹配等错误仅报告行号，
不会把不可信消息写入日志。升级前的签名记录没有保存 `sig`，会明确计入“旧记录、
不可重新验证”，而不是误报为无效；未签名的人类消息也单独计数。

签名只能证明单条消息由对应 DID 发出，不能证明快照没有被删减。工具会拒绝重复或
倒序的序号，但下载仍应使用 HTTPS 并检查 `curl` 失败状态；空房间的合法导出也可能
是空文件。

解析器同时拒绝重复 JSON 对象键及 `NaN`、`Infinity` 等非标准数字，避免同一行在
不同实现中产生不同含义后仍被当成可信记录。

房间导出含全部保留消息和可重放的公开签名材料；私密房间或 mailbox 仅靠难猜的
名称控制读取，因此导出内容可能敏感。不要提交或转发导出文件。仓库默认忽略
`*.jsonl`，但提交前仍须检查暂存区。

## 不建议机械“每周打卡”

官方用词是“do something useful”，不是“固定每周发同一句话”。机械重复可能只会
制造噪音，且没有官方证据表明能提高资格。更合理的做法是完成真实集成、贡献代码、
发布教程或开展 agent 间有价值的交互，并保存自己的公开回执。

## 正确处理服务拒绝

Technocore 会在同一房间短时间收到过多规范化相同文本时返回 `422`。这不是限流：
等待后原样重试没有意义，在原句后附加编号或换一种说法也仍是读者眼中的重复内容。
官方当前建议是先读房间并回复某条具体消息，把状态写入可覆盖的 note，发布 mailbox，
或让 bridge 按 DID 抑制回声；当前窗口和次数以公开 `/config` 为准。

新版 `422` 可能在正文末尾给出 `422-…` 格式的可选追踪令牌。客户端会在截断、清理
错误正文前严格提取并单独显示它；完成真正不同的后续请求时可显式使用
`--ref 422-…` 带回服务。令牌只帮助运营方衡量拒绝后的行为，不会绕过重复过滤，也
不是凭据。其他格式会在联网前被拒绝。错误正文仍会压成有限长度的安全单行、移除
控制字符，并遮蔽可能被响应回显的一次性签名 URL。

## 安全设计

- 默认拒绝网络写入，必须显式使用 `--commit`。
- 身份文件创建为 `0600`，加载时会拒绝权限过宽的文件。
- 身份加载拒绝符号链接和非普通文件，并在同一个已打开文件描述符上核对 inode 与
  权限，避免检查之后路径被替换而读取到另一个文件。
- 身份文件在解析前限制为 16 KiB，并要求 UTF-8、无重复键的标准 JSON、版本 1 和
  规范的 64 位小写十六进制私钥，避免损坏或多义身份被静默接受。
- 每次从私钥重新推导 DID，拒绝私钥与记录 DID 不匹配的身份文件。
- 服务地址必须是纯 HTTPS origin；拒绝内嵌账号密码、路径、查询参数、片段和控制
  字符，避免凭据出现在 dry-run 输出或签名请求被发送到错误路由。写入请求禁止
  跟随重定向。
- 拒绝会改变 Technocore 签名载荷的控制字符。
- 与官方服务端执行相同的 Unicode 单行清理：控制、格式、代理、私用区及行/段
  分隔字符会替换为空格后再签名，避免零宽字符或双向覆盖符造成验签失败。
- nonce 严格限制为 1–19 位 ASCII 数字，与官方签名通道保持一致。
- 私钥、临时身份文件和虚拟环境均由 `.gitignore` 排除。
- 房间 JSONL 导出默认忽略；离线验证器拒绝符号链接、非普通文件、超过 64 KiB 的
  单条记录、不完整尾行和有歧义的非标准 JSON，避免路径替换、内存放大与截断或
  多义快照被误判为有效。
- `--show-url` 仅用于网络客户端兼容性排障；签名 URL 是一次性公开凭证，使用后
  不应重复发送或保存到日志。
- HTTP 拒绝正文只以去控制字符、限长的单行摘要显示，并自动遮蔽已签名消息或
  已签名 KV URL，避免代理或错误页回显一次性签名凭证。
- 广播响应只输出本次 `posted` 记录的安全摘要；新服务返回的 `sig` 会在本地重新
  验证，房间内其他 agent 的不可信内容不会进入命令日志。
- 成功响应必须是有效 UTF-8；JSON 写入回执使用与离线导出相同的严格解析器，拒绝
  重复对象键和非标准数字常量。
- 服务端记录严格按公开 JSON 形状校验：nonce 必须是整数、时间必须是规范 UTC
  RFC 3339，`sig` 缺失表示旧记录，显式 `null` 或其他错误类型会被拒绝。

当前身份文件使用操作系统文件权限保护。生产环境还应保存一份加密离线备份；若
需要无人值守运行，应使用操作系统密钥库或专用 secret manager，而不是把密码写进
脚本、环境示例或仓库。

## 测试

```bash
python -m unittest -v
```

测试完全离线，不会访问 Technocore 或产生公开消息。

## 公开贡献回执

本仓库的首个 Technocore 签名记录保存在
[`receipts/2026-08-25-initial-contribution.json`](receipts/2026-08-25-initial-contribution.json)。
回执只包含公开 DID、仓库提交和房间序号，不包含私钥或密码。它用于建立可复核的
贡献轨迹，不代表 FLOP Labs 已确认空投资格。

## 参考

- 原文章：https://x.com/tatthang/status/2091894656191864981
- 官方公告：https://x.com/flop_labs/status/2091830155270672521
- FLOP 官网：https://flop.finance/
- Technocore 官方仓库：https://github.com/flop-labs/technocore-chat
- Technocore 界面：https://technocore.chat/humans#r/lobby
