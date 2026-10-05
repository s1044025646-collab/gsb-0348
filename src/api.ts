// 纯 node:http 实现的 JSON API，无外部依赖。
import http from "node:http";
import { ApiError } from "./errors.js";
import * as svc from "./service.js";

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(payload);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > 1024 * 1024) { reject(new ApiError("LIMIT_EXCEEDED", "请求体过大", 413)); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseJsonBody(raw: string): Record<string, unknown> {
  if (!raw.trim()) return {};
  try {
    const v = JSON.parse(raw);
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error();
    return v as Record<string, unknown>;
  } catch {
    throw new ApiError("INVALID_ARGUMENT", "请求体必须是 JSON 对象", 400);
  }
}

function requireString(v: unknown, name: string): string {
  if (typeof v !== "string" || v.length === 0) {
    throw new ApiError("INVALID_ARGUMENT", `参数 ${name} 必须是非空字符串`, 400);
  }
  return v;
}

function parseId(seg: string | undefined, name: string): number {
  const n = Number(seg);
  if (!Number.isInteger(n) || n < 0) {
    throw new ApiError("INVALID_ARGUMENT", `路径参数 ${name} 必须是非负整数`, 400);
  }
  return n;
}

function optPort(v: string | null): number | undefined {
  if (v === null) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new ApiError("INVALID_ARGUMENT", `端口必须是 0-65535 的整数`, 400);
  }
  return n;
}

export async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const parts = url.pathname.split("/").filter(Boolean);
  const method = req.method ?? "GET";
  try {
    // GET /api/limits
    if (method === "GET" && url.pathname === "/api/limits") {
      return sendJson(res, 200, svc.getLimits());
    }
    // GET /api/files
    if (method === "GET" && url.pathname === "/api/files") {
      return sendJson(res, 200, svc.listFiles());
    }
    // POST /api/import  {path}
    if (method === "POST" && url.pathname === "/api/import") {
      const body = parseJsonBody(await readBody(req));
      const p = requireString(body.path, "path");
      return sendJson(res, 201, svc.importFile(p));
    }
    if (parts[0] === "api" && parts[1] === "files" && parts.length >= 3) {
      const fileId = parseId(parts[2], "fileId");
      const sub = parts[3];
      // POST /api/files/:id/validate
      if (method === "POST" && sub === "validate" && parts.length === 4) {
        return sendJson(res, 200, svc.validateFile(fileId));
      }
      // GET /api/files/:id/packets
      if (method === "GET" && sub === "packets" && parts.length === 4) {
        return sendJson(res, 200, svc.listPackets(fileId));
      }
      // GET /api/files/:id/packets/:idx  |  /raw
      if (method === "GET" && sub === "packets" && parts.length === 5) {
        const idx = parseId(parts[4], "recordIndex");
        return sendJson(res, 200, svc.getRecordDetail(fileId, idx));
      }
      if (method === "GET" && sub === "packets" && parts.length === 6 && parts[5] === "raw") {
        const idx = parseId(parts[4], "recordIndex");
        const detail = svc.getRecordDetail(fileId, idx);
        return sendJson(res, 200, svc.getRawBytes(fileId, detail.record.data_offset, detail.record.incl_len));
      }
      // GET /api/files/:id/raw?offset=&length=
      if (method === "GET" && sub === "raw" && parts.length === 4) {
        const offset = Number(url.searchParams.get("offset"));
        const length = Number(url.searchParams.get("length"));
        return sendJson(res, 200, svc.getRawBytes(fileId, offset, length));
      }
      // GET /api/files/:id/udp?src=&dst=&sport=&dport=
      if (method === "GET" && sub === "udp" && parts.length === 4) {
        return sendJson(res, 200, svc.filterUdp(fileId, {
          src: url.searchParams.get("src") ?? undefined,
          dst: url.searchParams.get("dst") ?? undefined,
          sport: optPort(url.searchParams.get("sport")),
          dport: optPort(url.searchParams.get("dport")),
        }));
      }
      // GET /api/files/:id/report
      if (method === "GET" && sub === "report" && parts.length === 4) {
        return sendJson(res, 200, svc.exportReport(fileId));
      }
      // GET /api/files/:id/diagnostics
      if (method === "GET" && sub === "diagnostics" && parts.length === 4) {
        return sendJson(res, 200, svc.getDiagnostics(fileId));
      }
    }
    throw new ApiError("NOT_FOUND", `未知路由 ${method} ${url.pathname}`, 404);
  } catch (e) {
    if (e instanceof ApiError) {
      return sendJson(res, e.httpStatus, { error: { code: e.code, message: e.message, details: e.details ?? null } });
    }
    const msg = e instanceof Error ? e.message : String(e);
    return sendJson(res, 500, { error: { code: "INTERNAL", message: msg } });
  }
}

export function startServer(port: number): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer((req, res) => { void handleRequest(req, res); });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const actual = typeof addr === "object" && addr ? addr.port : port;
      resolve({ server, port: actual });
    });
  });
}
