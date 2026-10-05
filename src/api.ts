import http from "node:http";
import path from "node:path";
import { Store } from "./db.js";
import { DEFAULT_LIMITS } from "./pcap.js";

function send(res: http.ServerResponse, code: number, body: unknown) {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(code, { "content-type": "application/json; charset=utf-8" });
  res.end(json);
}

function sendErr(res: http.ServerResponse, err: any) {
  const code = err?.code ?? "E_INTERNAL";
  const status =
    code === "E_NOT_FOUND" ? 404 :
    code === "E_INVALID_PARAM" || code === "E_PATH_OUTSIDE" || code === "E_OUT_OF_RANGE" ? 400 :
    code === "E_HASH_MISMATCH" || code === "E_STORED_MISSING" ? 409 : 500;
  send(res, status, { error: { code, message: String(err?.message ?? err) } });
}

async function readBody(req: http.IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 1024 * 1024) throw Object.assign(new Error("body too large"), { code: "E_INVALID_PARAM" });
    chunks.push(c as Buffer);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("invalid JSON body"), { code: "E_INVALID_PARAM" });
  }
}

export function createServer(store: Store, projectRoot: string) {
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const parts = url.pathname.split("/").filter(Boolean);
      const method = req.method ?? "GET";

      if (method === "GET" && url.pathname === "/limits") {
        return send(res, 200, {
          limits: store.limits,
          defaults: DEFAULT_LIMITS,
          supported: {
            format: "classic pcap, version 2.4 only",
            endianness: ["little", "big"],
            precision: ["microsecond", "nanosecond"],
            linktype: "Ethernet (1)",
            decoded: ["Ethernet", "IPv4 (unfragmented, options via IHL)", "UDP"],
            notSupported: ["pcapng", "live capture", "TCP reassembly", "IPv6", "external protocol libs"],
          },
        });
      }
      if (method === "POST" && url.pathname === "/captures") {
        const body = await readBody(req);
        if (typeof body.path !== "string" || body.path.length === 0) {
          return sendErr(res, Object.assign(new Error("missing 'path' (project-relative file)"), { code: "E_INVALID_PARAM" }));
        }
        const abs = path.resolve(projectRoot, body.path);
        return send(res, 201, store.importCapture(abs, projectRoot));
      }
      if (method === "GET" && url.pathname === "/captures") {
        return send(res, 200, store.listCaptures());
      }
      if (parts[0] === "captures" && parts.length >= 2) {
        const id = Number(parts[1]);
        if (!Number.isInteger(id)) return sendErr(res, Object.assign(new Error("invalid capture id"), { code: "E_INVALID_PARAM" }));
        const sub = parts[2];
        if (method === "GET" && parts.length === 2) {
          const cap = store.getCapture(id);
          if (!cap) return sendErr(res, Object.assign(new Error(`capture ${id} not found`), { code: "E_NOT_FOUND" }));
          return send(res, 200, cap);
        }
        if (method === "GET" && sub === "validate") return send(res, 200, store.validate(id));
        if (method === "GET" && sub === "report") return send(res, 200, store.report(id));
        if (method === "GET" && sub === "packets" && parts.length === 3) {
          const f = {
            srcIp: url.searchParams.get("src") ?? undefined,
            dstIp: url.searchParams.get("dst") ?? undefined,
            srcPort: url.searchParams.has("srcPort") ? Number(url.searchParams.get("srcPort")) : undefined,
            dstPort: url.searchParams.has("dstPort") ? Number(url.searchParams.get("dstPort")) : undefined,
          };
          const filtered = f.srcIp || f.dstIp || f.srcPort !== undefined || f.dstPort !== undefined;
          return send(res, 200, filtered ? store.filterUdp(id, f) : store.listPackets(id));
        }
        if (method === "GET" && sub === "packets" && parts.length === 4) {
          const idx = Number(parts[3]);
          if (!Number.isInteger(idx)) return sendErr(res, Object.assign(new Error("invalid packet index"), { code: "E_INVALID_PARAM" }));
          return send(res, 200, store.packetDetail(id, idx));
        }
        if (method === "GET" && sub === "raw") {
          const offset = Number(url.searchParams.get("offset") ?? "NaN");
          const length = Number(url.searchParams.get("length") ?? "NaN");
          return send(res, 200, store.rawSlice(id, offset, length));
        }
      }
      sendErr(res, Object.assign(new Error(`no route: ${method} ${url.pathname}`), { code: "E_NOT_FOUND" }));
    } catch (err) {
      sendErr(res, err);
    }
  });
}

/** Listen on requested port, or pick a free one when port=0 (default). */
export function startServer(store: Store, projectRoot: string, port = 0, host = "127.0.0.1") {
  const server = createServer(store, projectRoot);
  return new Promise<{ server: http.Server; port: number }>((resolve) => {
    server.listen(port, host, () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === "object" && addr ? addr.port : port });
    });
  });
}
