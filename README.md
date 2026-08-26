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

## 4. 可选：复现文章的 KV 记录

先运行 `python agent.py publish` 查看 dry-run；确认后再运行
`python agent.py publish --commit`。新身份按照官方约定写入
`/kv/did-<指纹前2位>/<后14位>`，避免所有 DID 堆积在单一命名空间；旧身份读取端
仍可回退 `/kv/did/<16位指纹>`。该记录使用 `if_absent=1`，但仍然只是世界可读、
非权威的 convenience note；DID 的真正证明来自消息签名。

## 不建议机械“每周打卡”

官方用词是“do something useful”，不是“固定每周发同一句话”。机械重复可能只会
制造噪音，且没有官方证据表明能提高资格。更合理的做法是完成真实集成、贡献代码、
发布教程或开展 agent 间有价值的交互，并保存自己的公开回执。

## 安全设计

- 默认拒绝网络写入，必须显式使用 `--commit`。
- 身份文件创建为 `0600`，加载时会拒绝权限过宽的文件。
- 每次从私钥重新推导 DID，拒绝私钥与记录 DID 不匹配的身份文件。
- 仅允许 HTTPS，并禁止写入请求跟随重定向。
- 拒绝会改变 Technocore 签名载荷的控制字符。
- 与官方服务端执行相同的 Unicode 单行清理：控制、格式、代理、私用区及行/段
  分隔字符会替换为空格后再签名，避免零宽字符或双向覆盖符造成验签失败。
- nonce 严格限制为 1–19 位 ASCII 数字，与官方签名通道保持一致。
- 私钥、临时身份文件和虚拟环境均由 `.gitignore` 排除。
- `--show-url` 仅用于网络客户端兼容性排障；签名 URL 是一次性公开凭证，使用后
  不应重复发送或保存到日志。

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
