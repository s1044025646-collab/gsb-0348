import path from "node:path";
import { Store } from "./db.js";
import { startServer } from "./api.js";

const PROJECT_ROOT = path.resolve(process.cwd());
const DATA_DIR = process.env.PCAP_DATA_DIR ?? path.join(PROJECT_ROOT, "data");

function fmtPacket(p: any): string {
  const ts = `${p.ts_sec}.${String(p.ts_frac).padStart(6, "0")}`;
  const len = `${p.incl_len}/${p.orig_len}`;
  const flow =
    p.udp_src_port != null
      ? `${p.ip_src}:${p.udp_src_port} -> ${p.ip_dst}:${p.udp_dst_port}`
      : p.ip_src
        ? `${p.ip_src} -> ${p.ip_dst}`
        : "-";
  return `#${String(p.idx).padStart(4)} ts=${ts} len=${len} ${flow} [${p.status}${p.reason ? ": " + p.reason : ""}]`;
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const store = new Store(DATA_DIR);
  const json = (v: unknown) => console.log(JSON.stringify(v, null, 2));

  switch (cmd) {
    case "import": {
      const file = args[0];
      if (!file) throw new Error("usage: cli import <pcap-file-inside-project>");
      json(store.importCapture(path.resolve(PROJECT_ROOT, file), PROJECT_ROOT));
      break;
    }
    case "list":
      json(store.listCaptures());
      break;
    case "validate": {
      json(store.validate(Number(args[0])));
      break;
    }
    case "packets": {
      const rows = store.listPackets(Number(args[0])) as any[];
      for (const p of rows) console.log(fmtPacket(p));
      break;
    }
    case "show": {
      json(store.packetDetail(Number(args[0]), Number(args[1])));
      break;
    }
    case "raw": {
      json(store.rawSlice(Number(args[0]), Number(args[1]), Number(args[2])));
      break;
    }
    case "filter": {
      const [id, srcIp, dstIp, srcPort, dstPort] = args;
      const rows = store.filterUdp(Number(id), {
        srcIp: srcIp || undefined,
        dstIp: dstIp || undefined,
        srcPort: srcPort ? Number(srcPort) : undefined,
        dstPort: dstPort ? Number(dstPort) : undefined,
      }) as any[];
      for (const p of rows) console.log(fmtPacket(p));
      break;
    }
    case "report": {
      json(store.report(Number(args[0])));
      break;
    }
    case "serve": {
      const portArg = args[0] !== undefined ? Number(args[0]) : 0;
      if (!Number.isInteger(portArg) || portArg < 0 || portArg > 65535) throw new Error("invalid port");
      const { port } = await startServer(store, PROJECT_ROOT, portArg);
      console.log(`pcap-inspector API listening on http://127.0.0.1:${port}`);
      break;
    }
    default:
      console.log(`pcap-inspector CLI
usage:
  import <file>                 导入项目内 pcap 文件
  list                          列出所有抓包
  validate <id>                 重新校验容器（哈希 + 重新解析 + 索引比对）
  packets <id>                  列出数据包（包号/时间/长度/源目标/状态）
  show <id> <idx>               按记录读取协议层详情
  raw <id> <offset> <length>    查询原始偏移字节（hex）
  filter <id> [srcIp] [dstIp] [srcPort] [dstPort]   过滤已解析 UDP
  report <id>                   导出 JSON 报告
  serve [port]                  启动 API（缺省自动选择空闲端口）`);
  }
}

main().catch((e) => {
  console.error(`error [${e.code ?? "E_INTERNAL"}]: ${e.message}`);
  process.exit(1);
});
