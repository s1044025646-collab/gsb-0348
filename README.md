# pcap-inspector：经典 PCAP 离线检查后端

纯本地、离线的经典 PCAP（libpcap）抓包文件检查服务。只做 API 与 CLI，不抓包、不发包、
不拦截流量，不依赖 Docker / WSL / 在线服务。技术栈：TypeScript + Node.js（内置 `node:http`
与 `node:sqlite`，无任何第三方运行时依赖）。

## 支持范围

- 经典 PCAP **版本 2.4**，四种 magic：大端/小端 × 微秒/纳秒精度
- 仅 **Ethernet（linktype=1）** 链路类型
- 字段解析：Ethernet → IPv4（按 IHL 跳过选项，以 total length 约束网络层范围）→ 未分片 UDP
- 分片、IPv6、TCP 及其他封装：保留字节摘要并标记 `undecoded`，不伪装成完整 UDP
- 明确**不支持**：PCAPNG、实时抓包、TCP 重组、外部协议识别库

## 边界与完整性规则

- 每条记录区分 `incl_len`（已捕获）与 `orig_len`（原始长度）：`incl_len < orig_len` 是正常
  抓取截短（`truncated_capture`），不当坏文件；记录声明有字节而文件不足是容器截断
  （`E_TRUNCATED_RECORD_DATA`）
- 校验 snaplen、记录头完整性、子秒字段范围（微秒 < 1e6，纳秒 < 1e9）与剩余字节；
  损坏时报告**精确偏移与记录编号**
- 绝不越过当前包边界读下一条记录；尾部零字节不会被当作填充忽略（16 个零字节会被解析为
  一条合法的 incl=0 空记录，4 个零字节则报 `E_TRUNCATED_RECORD_HEADER`）
- 链路层填充（Ethernet 帧超出 IPv4 total length 的部分）不计入 UDP 载荷
- UDP 长度必须 ≥ 8 且不超过 IP 声明的载荷范围，否则标记 `inconsistent`
- 时间戳用 BigInt 计算，输出精确十进制纳秒字符串（`tsNs`），不经浮点，不丢低位
- 记录顺序保持文件原样，时间戳倒退也不静默排序

## 限制（可通过 `GET /limits` 查询）

- 文件大小上限 64 MiB，包数上限 1,000,000（`src/pcap.ts` 中 `DEFAULT_LIMITS`）
- 只读取项目目录内已存在的文件；拒绝项目外路径（`E_PATH_OUTSIDE`）

## 快速开始

```powershell
npm install        # 仅开发依赖 typescript / @types/node
npm run fixtures   # 生成 fixtures/ 下的合成夹具
npm test           # 构建并运行全部测试
npm start          # 启动 API（默认自动选择空闲端口，也可 npm start -- 8080）
npm run demo       # 端到端 CLI 演示
```

数据目录默认为项目内 `data/`（可用环境变量 `PCAP_DATA_DIR` 覆盖），导入的文件复制为
`data/files/<sha256>.pcap`，SQLite 库为 `data/pcap.db`。

## CLI

```
node dist/src/cli.js import <file>                导入项目内 pcap 文件
node dist/src/cli.js list                         列出所有抓包
node dist/src/cli.js validate <id>                校验容器（哈希 + 重解析 + 索引比对）
node dist/src/cli.js packets <id>                 列包（包号/时间/长度/源目标/解码状态）
node dist/src/cli.js show <id> <idx>              按记录读取协议层详情
node dist/src/cli.js raw <id> <offset> <length>   查询原始偏移字节（hex）
node dist/src/cli.js filter <id> [srcIp] [dstIp] [srcPort] [dstPort]
node dist/src/cli.js report <id>                  导出 JSON 报告
node dist/src/cli.js serve [port]                 启动 API（缺省自动选空闲端口）
```

## HTTP API（JSON）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/limits` | 支持范围与上限 |
| POST | `/captures` | 导入，body `{"path": "fixtures/x.pcap"}`（项目相对路径） |
| GET | `/captures` | 列出抓包 |
| GET | `/captures/:id` | 单个抓包元信息 |
| GET | `/captures/:id/validate` | 重新校验容器 |
| GET | `/captures/:id/packets` | 列包；查询参数 `src` `dst` `srcPort` `dstPort` 过滤已解析 UDP |
| GET | `/captures/:id/packets/:idx` | 协议层详情（从存储字节重新解析） |
| GET | `/captures/:id/raw?offset=&length=` | 原始字节（length ≤ 65536） |
| GET | `/captures/:id/report` | 导出完整报告 |

## 错误码

`E_BAD_MAGIC` `E_TRUNCATED_GLOBAL_HEADER` `E_BAD_VERSION` `E_BAD_SNAPLEN`
`E_UNSUPPORTED_LINKTYPE` `E_TRUNCATED_RECORD_HEADER` `E_TRUNCATED_RECORD_DATA`
`E_BAD_SUBSECOND` `E_INCL_GT_SNAPLEN` `E_INCL_GT_ORIG` `E_LIMIT_FILE_SIZE`
`E_LIMIT_PACKETS` `E_PATH_OUTSIDE` `E_NOT_FOUND` `E_INVALID_PARAM` `E_OUT_OF_RANGE`
`E_STORED_MISSING` `E_HASH_MISMATCH`

## 持久化与一致性

- SQLite 保存：文件 SHA-256、大小、格式版本、字节序、精度、snaplen、linktype、
  记录索引（偏移/时间戳/长度/解码结果）与诊断
- 导入失败不会登记为完全有效：头损坏为 `invalid`（无记录），中途损坏为 `partial`
  （保留已解析前缀 + 诊断）
- 原始字节以内容哈希命名存储；每次读取前重算 SHA-256，替换文件会触发
  `E_HASH_MISMATCH`，旧偏移不会指向新内容
- 重启后可用同一 `id` 重新读取记录并与原字节核对（`validate` 重解析并比对索引）

## 测试与夹具

`scripts/make-fixtures.ts` 生成合成夹具：小端微秒、大端纳秒、IPv4 选项、正常 UDP、
snaplen 截短、未支持协议、Ethernet 尾部填充、空抓包、坏 magic、半记录头、记录数据截断、
非法子秒、incl_len 越界。`test/` 共 30 个用例，手写字节布局独立核对偏移、端口、载荷与
纳秒值，并覆盖大小端语义一致性、失败不越界/不误吞下一包、重启读取与输入不可变性。

## 已知限制

- `node:sqlite` 在 Node 25 仍打印 ExperimentalWarning，不影响功能
- UDP 校验和、IP 校验和仅展示不验证；不支持链路类型 Ethernet 之外的封装
