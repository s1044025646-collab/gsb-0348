import { execFileSync } from "node:child_process";
import path from "node:path";

const node = process.execPath;
const cli = path.resolve("dist/src/cli.js");
const run = (args: string) => {
  console.log(`\n$ node dist/src/cli.js ${args}`);
  try {
    console.log(execFileSync(node, [cli, ...args.split(" ").filter(Boolean)], { encoding: "utf8" }).trim());
  } catch (e: any) {
    console.log(String(e.stdout ?? "").trim());
    console.error(String(e.stderr ?? "").trim());
  }
};

run("import fixtures/udp-le-micro.pcap");
run("import fixtures/udp-be-nano.pcap");
run("import fixtures/snaplen-truncated.pcap");
run("import fixtures/bad-magic.pcap");
run("list");
run("packets 1");
run("show 1 0");
run("filter 1 192.168.0.1 192.168.0.2 5000 6000");
run("validate 1");
run("raw 1 24 16");
run("report 3");
