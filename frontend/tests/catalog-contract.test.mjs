import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const catalog = readFileSync(new URL("../src/api/catalog.ts", import.meta.url), "utf8");
const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");

test("callable_name 只接受字符串值", () => {
  assert.match(catalog, /function text\(value: unknown\)[\s\S]*?typeof value === 'string'/);
  assert.doesNotMatch(catalog, /String\(value\)/);
  assert.match(catalog, /callable_name: text\(item\.callable_name \|\| item\.entrypoint \|\| item\.callable\)/);
});

test("流程进度使用 result_summary 聚合输出行数", () => {
  assert.match(app, /data\?\.output_lines \?\?[\s\S]*?outputEvents\.length/);
  assert.doesNotMatch(app, /legacySuppressed/);
  assert.match(app, /flowProgress\([\s\S]*?outputLineCount,[\s\S]*?reportedProgress/);
});
