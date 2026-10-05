import fs from "node:fs";
import path from "node:path";
import { pcapFile, udpFrame } from "../src/synth.js";

const dir = path.resolve(process.cwd(), "fixtures");
fs.mkdirSync(dir, { recursive: true });
const write = (name: string, buf: Buffer) => {
  fs.writeFileSync(path.join(dir, name), buf);
  console.log(`wrote fixtures/${name} (${buf.length} bytes)`);
};

// 1. little-endian, microsecond, normal UDP
write("udp-le-micro.pcap", pcapFile({ endianness: "le", precision: "micro" }, [
  { tsSec: 1700000000, tsFrac: 123456, data: udpFrame({ payload: Buffer.from("hello-udp") }) },
  { tsSec: 1700000001, tsFrac: 200, data: udpFrame({ srcPort: 53, dstPort: 5353, payload: Buffer.from("dns-like") }) },
]));

// 2. big-endian, nanosecond, same semantics as #1 record 0
write("udp-be-nano.pcap", pcapFile({ endianness: "be", precision: "nano" }, [
  { tsSec: 1700000000, tsFrac: 123456000, data: udpFrame({ payload: Buffer.from("hello-udp") }) },
]));

// 3. IPv4 with options (IHL=24)
write("ipv4-options.pcap", pcapFile({}, [
  { tsSec: 1700000100, tsFrac: 1, data: udpFrame({ ipOptions: Buffer.from([1, 1, 1, 0]) }) },
]));

// 4. snaplen-truncated capture (incl_len < orig_len)
write("snaplen-truncated.pcap", pcapFile({ snaplen: 96 }, (() => {
  const full = udpFrame({ payload: Buffer.alloc(200, 0x41) });
  return [{ tsSec: 1700000200, tsFrac: 999, data: full.subarray(0, 60), origLen: full.length }];
})()));

// 5. unsupported protocols: IPv6 ethertype + TCP
write("unsupported.pcap", pcapFile({}, [
  { tsSec: 1700000300, tsFrac: 0, data: udpFrame({ etherType: 0x86dd }) },
  { tsSec: 1700000301, tsFrac: 0, data: udpFrame({ protocol: 6 }) },
  { tsSec: 1700000302, tsFrac: 0, data: udpFrame({ fragField: 0x2000 }) },
]));

// 6. ethernet padding beyond IPv4 total length
write("eth-padding.pcap", pcapFile({}, [
  { tsSec: 1700000400, tsFrac: 7, data: udpFrame({ payload: Buffer.from("x"), padding: 18 }) },
]));

// 7. empty capture (header only)
write("empty.pcap", pcapFile({}, []));

// 8. bad magic
write("bad-magic.pcap", Buffer.from("DEADBEEF00000000000000000000000000000000", "hex"));

// 9. truncated record header
write("half-record-header.pcap", Buffer.concat([pcapFile({}, []), Buffer.alloc(8, 0)]));

// 10. record declares bytes the file does not have
write("truncated-record-data.pcap", (() => {
  const good = pcapFile({}, [{ tsSec: 1, tsFrac: 2, data: udpFrame() }]);
  const extra = Buffer.concat([pcapFile({}, []).subarray(24), Buffer.alloc(0)]);
  void extra;
  const hdr = Buffer.alloc(16);
  hdr.writeUInt32LE(2, 0); hdr.writeUInt32LE(3, 4);
  hdr.writeUInt32LE(100, 8); hdr.writeUInt32LE(100, 12);
  return Buffer.concat([good, hdr, Buffer.alloc(10)]);
})());

// 11. illegal subsecond field
write("bad-subsecond.pcap", (() => {
  const hdr = Buffer.alloc(16);
  hdr.writeUInt32LE(1, 0); hdr.writeUInt32LE(1_000_000, 4);
  hdr.writeUInt32LE(0, 8); hdr.writeUInt32LE(0, 12);
  return Buffer.concat([pcapFile({}, []), hdr]);
})());

// 12. incl_len beyond snaplen
write("incl-gt-snaplen.pcap", (() => {
  const f = udpFrame();
  const hdr = Buffer.alloc(16);
  hdr.writeUInt32LE(1, 0); hdr.writeUInt32LE(0, 4);
  hdr.writeUInt32LE(f.length, 8); hdr.writeUInt32LE(f.length, 12);
  return Buffer.concat([pcapFile({ snaplen: 10 }, []), hdr, f]);
})());

console.log("fixtures done");
