// CLI：import / validate / list / show / raw / filter / report / files / limits / serve
import { ApiError } from "./errors.js";
import * as svc from "./service.js";
import { startServer } from "./api.js";
import { timestampToNanoString, type SubsecPrecision } from "./pcap/parser.js";
import type { RecordRow } from "./store.js";

function out(v: unknown): void {
  console.log(typeof v === "string" ? v : JSON.stringify(v, null, 2));
}

function argValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

function fmtRow(r: RecordRow, precision: SubsecPrecision): string {
  const nano = timestampToNanoString(r.ts_sec, r.ts_subsec, precision);
  const ts = `${nano.slice(0, -9)}.${nano.slice(-9)}`;
  const len = `${r.incl_len}/${r.orig_len}`;
  const flow = r.ip_src
    ? `${r.ip_src}:${r.udp_sport ?? "-"} -> ${r.ip_dst}:${r.udp_dport ?? "-"}`
    : "(未解码)";
  return `#${String(r.idx).padStart(4)}  ${ts}  ${len.padStart(9)}  ${flow.padEnd(42)}  ${r.decode_status}`;
}

function printPackets(fileId: number, rows: RecordRow[]): void {
  const precision = svc.getFileRow(fileId).precision as SubsecPrecision;
  console.log("包号    时间戳                     incl/orig   源 -> 目标                                  解码状态");
  for (const r of rows) console.log(fmtRow(r, precision));
  console.log(`共 ${rows.length} 条`);
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  switch (cmd) {
    case "serve": {
      const portArg = argValue(args, "--port");
      const port = portArg !== undefined ? Number(portArg) : 0; // 默认自动选空闲端口
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        throw new ApiError("INVALID_ARGUMENT", "--port 必须是 0-65535 的整数", 400);
      }
      const { port: actual } = await startServer(port);
      console.log(`API 服务已启动: http://127.0.0.1:${actual}/api/limits`);
      return; // 保持进程
    }
    case "limits":
      return out(svc.getLimits());
    case "import": {
      const p = args[0];
      if (!p) throw new ApiError("INVALID_ARGUMENT", "用法: cli import <项目内pcap路径>", 400);
      return out(svc.importFile(p));
    }
    case "files":
      return out(svc.listFiles());
    case "validate": {
      const id = Number(args[0]);
      return out(svc.validateFile(id));
    }
    case "list": {
      const id = Number(args[0]);
      return printPackets(id, svc.listPackets(id));
    }
    case "show": {
      const id = Number(args[0]);
      const idx = Number(args[1]);
      return out(svc.getRecordDetail(id, idx));
    }
    case "raw": {
      const id = Number(args[0]);
      const offset = Number(argValue(args, "--offset") ?? args[1]);
      const length = Number(argValue(args, "--length") ?? args[2] ?? 64);
      return out(svc.getRawBytes(id, offset, length));
    }
    case "filter": {
      const id = Number(args[0]);
      const sport = argValue(args, "--sport");
      const dport = argValue(args, "--dport");
      return printPackets(id, svc.filterUdp(id, {
        src: argValue(args, "--src"),
        dst: argValue(args, "--dst"),
        sport: sport !== undefined ? Number(sport) : undefined,
        dport: dport !== undefined ? Number(dport) : undefined,
      }));
    }
    case "report": {
      const id = Number(args[0]);
      return out(svc.exportReport(id));
    }
    default:
      console.log(`用法: node dist/src/cli.js <命令>
  serve [--port N]     启动 API（默认自动选择空闲端口）
  limits               显示支持范围与上限
  import <path>        导入项目内 pcap 文件
  files                列出已导入文件
  validate <id>        重新校验容器
  list <id>            列出全部包
  show <id> <idx>      查看某条记录的协议层
  raw <id> --offset O --length L   读取原始偏移字节
  filter <id> [--src A] [--dst B] [--sport P] [--dport P]   过滤 UDP
  report <id>          导出 JSON 报告`);
  }
}

main().catch((e) => {
  if (e instanceof ApiError) {
    console.error(`错误[${e.code}] ${e.message}`);
    process.exit(2);
  }
  console.error(e);
  process.exit(1);
});
