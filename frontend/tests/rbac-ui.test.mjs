import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");

test("身份被显式传入任务、源码和修改工作台", () => {
  assert.match(app, /<FlowDrawer[\s\S]*?identity=\{identity\}/);
  assert.match(app, /<SourceWorkspace[\s\S]*?identity=\{identity\}/);
  assert.match(app, /<PatchWorkspace[\s\S]*?identity=\{identity\}/);
});

test("只读查看者不能触发任务、源码和修改写操作", () => {
  assert.equal(
    app.match(/const canWrite = \["admin", "analyst"\]\.includes\(identity\?\.role \|\| ""\)/g)?.length,
    4,
    "三个写操作工作区都必须采用明确角色白名单",
  );
  assert.match(app, /disabled=\{!canWrite \|\|[\s\S]*?action\("execute"\)/);
  assert.match(app, /disabled=\{!canWrite \|\|[\s\S]*?action\("cancel"\)/);
  assert.match(app, /disabled=\{!canWrite \|\|[\s\S]*?action\("retry"\)/);
  assert.match(app, /只读角色仅可查看和下载，不能保存源码或发起构建。/);
  assert.match(app, /只读角色仅可查看修改证据，不能上传、规划、执行、验证或回滚修改。/);
});

test("修改工作台默认使用中文指令并保留工程导出和高级模式", () => {
  assert.match(app, /大模型源码修改工作台/);
  assert.match(app, /APPLY_AI_SOURCE_CHANGES/);
  assert.match(app, /source\/archive/);
  assert.match(app, /高级十六进制/);
});

test("源码保存按钮可点击并在没有修改时给出原因", () => {
  assert.doesNotMatch(
    app,
    /disabled=\{!canWrite \|\| !!busy \|\| !selectedFile\?\.editable \|\| !dirty\}/,
  );
  assert.match(app, /当前文件没有需要保存的修改。请先在编辑器中修改内容。/);
  assert.match(app, /当前无修改，点击可查看提示/);
});

test("流程列表和最近流程支持删除", () => {
  assert.match(app, /method: "DELETE"/);
  assert.match(app, /删除流程「/);
  assert.match(app, /<ExperimentTable items=\{data\.experiments\.slice\(0, 8\)\} onDelete=/);
  assert.match(app, /<ExperimentTable items=\{items\} onSelect=\{onSelect\} selectedId=\{selected\?\.id\} onDelete=/);
  assert.match(app, /运行中的流程不能删除，请先取消或等待结束/);
});

test("前端工作台接入文件、终端和 ToolCall 控制", () => {
  assert.match(app, /fileAction\("batch-copy"/);
  assert.match(app, /fileAction\("batch-move"/);
  assert.match(app, /读取增量/);
  assert.match(app, /stopTerminalSession\(session\.id\)/);
  assert.match(app, /mutateToolCall\(call\.id, "retry"\)/);
  assert.match(app, /mutateToolCall\(call\.id, "cancel"\)/);
});

test("模型服务和权限管理视图只向管理员渲染", () => {
  assert.match(app, /view === "providers" && identity\?\.role === "admin"/);
  assert.match(app, /当前账号无权访问管理功能/);
});
