// 演示脚本：生成夹具 -> 导入 -> 列包 -> 查看记录 -> 过滤 -> 报告
import { execFileSync } from "node:child_process";
import path from "node:path";

const root = process.cwd();
const cli = path.join(root, "dist", "src", "cli.js");
const mkfx = path.join(root, "dist", "scripts", "make-fixtures.js");

const run = (args: string[]) => {
  console.log(`\n$ node ${args[0]} ${args.slice(1).join(" ")}`);
  try {
    process.stdout.write(execFileSync(process.execPath, args, { encoding: "utf8" }));
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string };
    process.stdout.write((err.stdout ?? "") + (err.stderr ?? ""));
  }
};

run([mkfx]);
run([cli, "limits"]);
run([cli, "import", "fixtures/le-usec.pcap"]);
run([cli, "import", "fixtures/snaplen-truncated.pcap"]);
run([cli, "import", "fixtures/length-overrun.pcap"]);
run([cli, "list", "1"]);
run([cli, "show", "1", "1"]);
run([cli, "filter", "1", "--dport", "53"]);
run([cli, "report", "3"]);
