# pcap-inspect — 离线经典 PCAP 检查服务

纯后端（API + CLI），使用 TypeScript / Node.js / SQLite（`node:sqlite`，无原生依赖），
Windows 本地运行，不需要 Docker / WSL / 在线服务。

## 支持范围（明确边界）

- 经典 PCAP（libpcap）格式，**仅版本 2.4**，**仅 Ethernet（linktype=1）**
- 小端 / 大端两种字节序；微秒 / 纳秒两种子秒精度
- 协议解码：Ethernet → IPv4（含选项，按 IHL 跳过；**不做分片重组**）→ UDP
- 只读取项目目录内**已存在**的文件：不捕获网卡、不发送数据包、不拦截流量
- 不支持：PCAPNG、TCP 重组、IPv6、外部协议识别库（未支持的协议保留字节摘要并标 `undecoded`）
- 上限（可用环境变量调整）：文件 ≤ 16 MiB（`PCAP_MAX_FILE_SIZE`），记录 ≤ 100000 条（`PCAP_MAX_RECORDS`）
- 记录顺序保持文件原样，即使时间戳倒退也不排序

## 边界与损坏处理原则

- 每条记录区分 `incl_len`（已捕获）与 `orig_len`（原始长度）：`incl_len < orig_len` 是正常 snaplen 截短
- 记录声明有字节但文件不足 → 容器截断，诊断含**偏移与记录编号**，不越界读取、不把尾部零字节当填充
- 解码状态区分：`decoded` / `incomplete_capture`（抓取截短）/ `contradiction`（字段自相矛盾）/ `fragmented` / `undecoded`
- IPv4 以 `total_length` 约束网络层范围，Ethernet 尾部填充不属于 UDP 载荷
- UDP `length` 必须 ≥ 8 且 ≤ IP 声明的载荷范围
- 时间戳保留原始秒与子秒字段，纳秒字符串用 BigInt 精确计算，不经过浮点

## 快速开始

```powershell
npm install        # 仅需 typescript / @types/node（devDependencies）
npm run fixtures   # 构建并生成合成夹具到 fixtures/
npm test           # 构建 + 生成夹具 + 运行全部测试
npm start          # 启动 API（默认自动选择空闲端口）
npm run demo       # 端到端演示
```

要求 Node.js ≥ 22.5（内置 `node:sqlite`）。

## CLI

```
node dist/src/cli.js serve [--port N]     # 启动 API；不带 --port 时自动选空闲端口
node dist/src/cli.js limits               # 支持范围与上限
node dist/src/cli.js import <path>        # 导入项目内 pcap（失败不登记为有效抓包）
node dist/src/cli.js files                # 已导入文件列表
node dist/src/cli.js validate <id>        # 重新校验容器
node dist/src/cli.js list <id>            # 包号/时间/长度/源目标/解码状态
node dist/src/cli.js show <id> <idx>      # 单条记录的协议层与纳秒时间戳
node dist/src/cli.js raw <id> --offset O --length L
node dist/src/cli.js filter <id> [--src A] [--dst B] [--sport P] [--dport P]
node dist/src/cli.js report <id>          # JSON 报告
```

## HTTP API（JSON，监听 127.0.0.1）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/limits` | 支持范围与上限 |
| POST | `/api/import` | 体：`{"path":"fixtures/x.pcap"}` |
| GET | `/api/files` | 已导入文件 |
| POST | `/api/files/:id/validate` | 重新校验容器 |
| GET | `/api/files/:id/packets` | 列包 |
| GET | `/api/files/:id/packets/:idx` | 单条记录协议层 |
| GET | `/api/files/:id/packets/:idx/raw` | 该记录的原始字节 |
| GET | `/api/files/:id/raw?offset=&length=` | 按文件偏移读原始字节 |
| GET | `/api/files/:id/udp?src=&dst=&sport=&dport=` | 过滤已解析 UDP |
| GET | `/api/files/:id/report` | 导出报告 |
| GET | `/api/files/:id/diagnostics` | 诊断列表 |

错误响应统一为 `{"error":{"code","message","details"}}`，错误码：
`INVALID_ARGUMENT` `NOT_FOUND` `UNSUPPORTED_FORMAT` `CORRUPT_FILE`
`LIMIT_EXCEEDED` `PATH_OUT_OF_SCOPE` `FILE_CHANGED` `INTERNAL`。

## 存储与一致性

- 数据目录默认为项目内 `data/`（`PCAP_DATA_DIR` 可改）：SQLite 库 + `blobs/<sha256>.pcap` 固定副本
- 导入时复制原文件为固定副本并记录 SHA-256；之后替换/改动源文件不影响旧偏移
- 每次按偏移读字节前重算副本摘要，不一致返回 `FILE_CHANGED`
- 容器截断的文件以 `partial` 状态保留已解析前缀与诊断；格式非法的文件导入直接失败、不登记
- 重启后按记录读取会从固定副本重新解析并核对偏移

## 测试夹具（`npm run fixtures` 生成）

`le-usec` / `be-nsec`（同语义帧的大小端+两种精度对照）、`snaplen-truncated`、
`unsupported-arp`、`empty`、`bad-magic`、`half-record-header`、`length-overrun`、
`bad-subsec`、`fragmented`、`eth-padding`、`udp-len-contradiction`、`out-of-order-ts`。

## 已知限制

- 不校验 IP/UDP 校验和；不重组分片；不识别 IPv6/TCP
- UDP 过滤仅匹配已完整解析出端口的记录
- 时间戳秒字段按 32 位无符号处理（与经典 PCAP 一致）
