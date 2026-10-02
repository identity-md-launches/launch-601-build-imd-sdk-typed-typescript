#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { ImdClient, LocalPrivateKeySigner } from "./index.js";

const warning = [
  "Experimental, commissioned as a test of the IMD swarm. It may not work as described.",
  "Read the code, start with small amounts, no warranty.",
].join(" ");
const help = [
  warning,
  "",
  "Usage: imd <command> [arguments] [--json]",
  "",
  "Commands:",
  "  capabilities",
  "  check <file>                 JSON: { action, input }",
  "  import <url>",
  "  quote <file>                 JSON: { action, input }",
  "  pay <order> [--execute]      dry run by default; --execute signs",
  "  status <order>",
  "  job <id>",
  "  schedules <owner>",
  "",
  "Environment: IMD_API, IMD_REQUEST_TOKEN, IMD_PRIVATE_KEY (only read with pay --execute).",
].join("\n");
const args = process.argv.slice(2),
  json = args.includes("--json"),
  execute = args.includes("--execute");
const clean = args.filter((x) => x !== "--json" && x !== "--execute");
const show = (v) =>
  console.log(
    json
      ? JSON.stringify(v, null, 2)
      : typeof v === "string"
        ? v
        : JSON.stringify(v, null, 2),
  );
async function body(file) {
  return JSON.parse(await readFile(file, "utf8"));
}
try {
  const [command, arg] = clean;
  if (!command || ["-h", "--help", "help"].includes(command)) {
    console.log(help);
    process.exit(0);
  }
  const client = new ImdClient({
    baseUrl: process.env.IMD_API,
    token: process.env.IMD_REQUEST_TOKEN,
    maxPerRequest: process.env.IMD_MAX_PER_REQUEST,
    maxPerDay: process.env.IMD_MAX_PER_DAY,
  });
  let out;
  if (command === "capabilities") out = await client.capabilities();
  else if (command === "check") {
    const v = await body(arg);
    out = await client.check(v.action, v.input);
  } else if (command === "import") out = await client.importRepo(arg);
  else if (command === "quote") {
    const v = await body(arg);
    out = await client.quote(v.action, v.input);
  } else if (command === "pay") {
    let signer;
    if (execute) {
      if (!process.env.IMD_PRIVATE_KEY)
        throw new Error("IMD_PRIVATE_KEY is required only for --execute");
      signer = new LocalPrivateKeySigner(process.env.IMD_PRIVATE_KEY);
    }
    out = await client.pay(arg, signer, { execute });
  } else if (command === "status") out = await client.status(arg);
  else if (command === "job") out = await client.job(arg);
  else if (command === "schedules") out = await client.schedules(arg);
  else throw new Error(`unknown command: ${command}`);
  show(out);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
