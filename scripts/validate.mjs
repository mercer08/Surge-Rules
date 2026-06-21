#!/usr/bin/env node

import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RULE_SET_DIR = path.join(ROOT, "public/rule-sets");
const ALLOWED_TYPES = new Set([
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN-WILDCARD",
  "IP-CIDR",
  "IP-CIDR6",
  "PROCESS-NAME",
  "URL-REGEX",
  "USER-AGENT",
]);

function isCommentOrBlank(line) {
  const trimmed = line.trim();
  return !trimmed || trimmed.startsWith("#") || trimmed.startsWith("//") || trimmed.startsWith(";");
}

function validateLine(file, line, lineNumber) {
  if (isCommentOrBlank(line)) return;
  if (line.includes("<html") || line.includes("<!DOCTYPE")) {
    throw new Error(`${file}:${lineNumber}: unexpected HTML content`);
  }
  if (/password=|username=|token=|ss:\/\/|trojan:\/\/|vmess:\/\/|vless:\/\//i.test(line)) {
    throw new Error(`${file}:${lineNumber}: possible secret`);
  }

  const [type, value] = line.split(",", 2);
  if (!ALLOWED_TYPES.has(type)) {
    throw new Error(`${file}:${lineNumber}: unsupported rule type ${type}`);
  }
  if (!value) {
    throw new Error(`${file}:${lineNumber}: missing rule value`);
  }
}

async function listRuleFiles(dir) {
  const entries = await readdir(dir);
  return entries.filter((entry) => entry.endsWith(".list")).map((entry) => path.join(dir, entry));
}

try {
  const dirInfo = await stat(RULE_SET_DIR);
  if (!dirInfo.isDirectory()) throw new Error(`${RULE_SET_DIR} is not a directory`);

  const files = await listRuleFiles(RULE_SET_DIR);
  if (files.length === 0) throw new Error("no .list files found");

  for (const file of files) {
    const text = await readFile(file, "utf8");
    if (!text.trim()) throw new Error(`${file}: empty file`);
    text.split(/\r?\n/).forEach((line, index) => validateLine(path.relative(ROOT, file), line, index + 1));
    console.log(`checked ${path.relative(ROOT, file)}`);
  }
} catch (error) {
  console.error(`Validation failed: ${error.message}`);
  process.exitCode = 1;
}
