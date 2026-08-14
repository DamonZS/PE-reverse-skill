package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const aiPatchConfirmation = "APPLY_AI_SOURCE_CHANGES"
const aiPatchRollbackConfirmation = "ROLLBACK_AI_SOURCE_CHANGES"
const aiWorkflowPlanConfirmation = "CONFIRM_AI_WORKFLOW_PLAN"

type aiWorkflowPlan struct {
	ID             string   `json:"id"`
	ExperimentID   string   `json:"experiment_id"`
	Workflow       string   `json:"workflow"`
	Status         string   `json:"status"`
	Instruction    string   `json:"instruction"`
	TargetIdentity string   `json:"target_identity"`
	LocationBasis  string   `json:"location_basis"`
	PID            int      `json:"pid,omitempty"`
	Address        string   `json:"address,omitempty"`
	ExpectedHex    string   `json:"expected_hex,omitempty"`
	DataHex        string   `json:"data_hex,omitempty"`
	DLLPath        string   `json:"dll_path,omitempty"`
	Method         string   `json:"method,omitempty"`
	ModuleSource   string   `json:"module_source,omitempty"`
	Evidence       []string `json:"evidence"`
	Validation     []string `json:"validation"`
	Risks          []string `json:"risks"`
	Rollback       []string `json:"rollback"`
	Provider       string   `json:"provider"`
	Model          string   `json:"model"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

type aiWorkflowModelResult struct {
	Summary        string   `json:"summary"`
	TargetIdentity string   `json:"target_identity"`
	LocationBasis  string   `json:"location_basis"`
	PID            int      `json:"pid"`
	Address        string   `json:"address"`
	ExpectedHex    string   `json:"expected_hex"`
	DataHex        string   `json:"data_hex"`
	DLLPath        string   `json:"dll_path"`
	Method         string   `json:"method"`
	ModuleSource   string   `json:"module_source"`
	Evidence       []string `json:"evidence"`
	Validation     []string `json:"validation"`
	Risks          []string `json:"risks"`
	Rollback       []string `json:"rollback"`
}

type aiSourceChange struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"before_sha256"`
	Before       string `json:"before"`
	After        string `json:"after"`
	Reason       string `json:"reason"`
}

type aiPatchPlan struct {
	ID           string           `json:"id"`
	ExperimentID string           `json:"experiment_id"`
	Status       string           `json:"status"`
	Mode         string           `json:"mode"`
	Instruction  string           `json:"instruction"`
	Summary      string           `json:"summary"`
	Evidence     []string         `json:"evidence"`
	Changes      []aiSourceChange `json:"source_changes"`
	Validation   []string         `json:"validation"`
	Risks        []string         `json:"risks"`
	Provider     string           `json:"provider"`
	Model        string           `json:"model"`
	CreatedAt    string           `json:"created_at"`
	UpdatedAt    string           `json:"updated_at"`
	Error        string           `json:"error,omitempty"`
}

type aiPatchModelResult struct {
	Mode     string   `json:"mode"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence"`
	Changes  []struct {
		Path   string `json:"path"`
		After  string `json:"after"`
		Reason string `json:"reason"`
	} `json:"source_changes"`
	Validation    []string `json:"validation"`
	Risks         []string `json:"risks"`
	NeedsEvidence string   `json:"needs_evidence"`
}

func (s *Server) aiPatch(w http.ResponseWriter, r *http.Request, id, action string) {
	project, err := s.findSourceProject(id)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "请先完成反编译和源码工程生成，再使用指令修改。"})
		return
	}
	switch action {
	case "ai-plan":
		var payload struct{ Instruction, Target, Mode string }
		if readJSON(r, &payload) != nil || len(strings.TrimSpace(payload.Instruction)) < 4 || len(payload.Instruction) > 4000 {
			bad(w, "请输入 4 到 4000 个字符的明确修改指令。")
			return
		}
		plan, planErr := s.createAIPatchPlan(r.Context(), id, project, payload.Instruction, payload.Target, payload.Mode)
		if planErr != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": planErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"plan": plan, "apply_confirmation": aiPatchConfirmation})
	case "ai-apply":
		var payload struct{ PlanID, Confirmation string }
		if readJSON(r, &payload) != nil || payload.Confirmation != aiPatchConfirmation {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "应用源码修改需要显式确认。"})
			return
		}
		plan, applyErr := s.applyAIPatchPlan(id, project, payload.PlanID)
		respond(w, map[string]any{"plan": plan}, applyErr)
	case "ai-rollback":
		var payload struct{ PlanID, Confirmation string }
		if readJSON(r, &payload) != nil || payload.Confirmation != aiPatchRollbackConfirmation {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "回滚源码修改需要显式确认。"})
			return
		}
		plan, rollbackErr := s.rollbackAIPatchPlan(id, project, payload.PlanID)
		respond(w, map[string]any{"plan": plan}, rollbackErr)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) workflowAIPlan(w http.ResponseWriter, r *http.Request, id string) {
	experiment, err := s.loadExperiment(id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	workflow := workflowTypeOf(experiment)
	if workflow != "memory_patch" && workflow != "process_injection" {
		bad(w, "只有动态内存补丁和进程内注入作业需要此 AI 计划")
		return
	}
	if experiment.Status != "awaiting_ai_plan" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "当前作业不处于等待 AI 计划状态"})
		return
	}
	plan, err := s.createWorkflowAIPlan(r.Context(), experiment)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	respond(w, map[string]any{"plan": plan, "confirmation": aiWorkflowPlanConfirmation}, nil)
}

func (s *Server) createWorkflowAIPlan(ctx context.Context, experiment Experiment) (aiWorkflowPlan, error) {
	params, _ := experiment.Metadata["workflow_params"].(map[string]any)
	instruction := strings.TrimSpace(fmt.Sprint(params["instruction"]))
	if instruction == "" || instruction == "<nil>" {
		return aiWorkflowPlan{}, errors.New("作业缺少修改需求")
	}
	profile, fallback := s.selectProvider("")
	if profile.Kind == "local" || !s.providerReady(profile) {
		return aiWorkflowPlan{}, errors.New("没有可用的大模型服务，请先在模型服务管理中完成连接测试")
	}
	input := map[string]any{"workflow": workflowTypeOf(experiment), "instruction": instruction, "target_program": experiment.Sample, "target_process": params["target_process"], "authorization": params["authorization_statement"], "constraints": params["constraints"], "validation_requirements": params["validation_requirements"], "module_source": params["module_source"], "rules": []string{"只能生成用于用户授权本地目标的方案", "必须给出目标身份和定位依据", "证据不足时返回空 PID、地址、字节或 DLL 路径", "不得生成持久化、规避检测或未授权远程访问能力", "动态内存写入必须包含 expected_hex、data_hex 和回滚步骤"}}
	model, usage, err := invokeAIWorkflowProvider(ctx, profile, input)
	s.recordProviderUsage(profile.Name, 1, err != nil, usageTokens(usage, "input_tokens"), usageTokens(usage, "output_tokens"))
	if err != nil {
		return aiWorkflowPlan{}, err
	}
	plan := aiWorkflowPlan{ID: newID(), ExperimentID: experiment.ID, Workflow: workflowTypeOf(experiment), Status: "planned", Instruction: instruction, TargetIdentity: model.TargetIdentity, LocationBasis: model.LocationBasis, PID: model.PID, Address: model.Address, ExpectedHex: compactHex(model.ExpectedHex), DataHex: compactHex(model.DataHex), DLLPath: model.DLLPath, Method: model.Method, ModuleSource: model.ModuleSource, Evidence: model.Evidence, Validation: model.Validation, Risks: model.Risks, Rollback: model.Rollback, Provider: profile.Name, Model: profile.Model, CreatedAt: now(), UpdatedAt: now()}
	if err := validateWorkflowAIPlan(plan, s.cfg.Workspace); err != nil {
		return aiWorkflowPlan{}, err
	}
	if plan.DLLPath != "" {
		plan.DLLPath, _ = filepath.Abs(plan.DLLPath)
	}
	root := filepath.Join(s.patchRoot(experiment.ID), "workflow-ai", plan.ID)
	if err := os.MkdirAll(root, 0700); err != nil {
		return aiWorkflowPlan{}, err
	}
	if err := writeFileJSON(filepath.Join(root, "plan.json"), plan); err != nil {
		return aiWorkflowPlan{}, err
	}
	if _, err := s.mutateExperiment(experiment.ID, func(current *Experiment) error {
		current.Metadata["workflow_ai_plan"] = map[string]any{"id": plan.ID, "status": plan.Status, "provider": plan.Provider, "model": plan.Model}
		*current = s.status(*current, "planned", "AI 已生成待确认的动态补丁方案")
		return nil
	}); err != nil {
		return aiWorkflowPlan{}, err
	}
	s.appendEvent(experiment.ID, "workflow_ai_plan_created", "planned", "大模型已生成结构化动态补丁方案，等待人工确认", map[string]any{"plan_id": plan.ID, "provider": profile.Name, "model": profile.Model, "provider_fallback": fallback})
	return plan, nil
}

func validateWorkflowAIPlan(plan aiWorkflowPlan, workspace string) error {
	if plan.TargetIdentity == "" || plan.LocationBasis == "" || len(plan.Evidence) == 0 || len(plan.Validation) == 0 || len(plan.Rollback) == 0 {
		return errors.New("模型计划缺少目标身份、定位依据、证据、验证或回滚信息")
	}
	if plan.PID <= 0 {
		return errors.New("模型未能提供经过证据支持的本地进程标识")
	}
	if plan.Workflow == "memory_patch" {
		if plan.Address == "" || plan.ExpectedHex == "" || plan.DataHex == "" || len(plan.ExpectedHex) != len(plan.DataHex) {
			return errors.New("模型计划缺少可验证的内存地址或前后字节")
		}
		return nil
	}
	if plan.Method != "load_library" || plan.DLLPath == "" {
		return errors.New("模型计划仅允许具备明确 DLL 路径的 load_library 注入")
	}
	resolved, err := filepath.Abs(plan.DLLPath)
	workspaceAbs, workspaceErr := filepath.Abs(workspace)
	if err != nil || workspaceErr != nil {
		return errors.New("无法解析模型计划路径")
	}
	rel, relErr := filepath.Rel(workspaceAbs, resolved)
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("模型计划中的 DLL 必须位于工作区")
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		return errors.New("模型计划中的 DLL 文件不存在")
	}
	plan.DLLPath = resolved
	return nil
}

func (s *Server) workflowAIConfirm(w http.ResponseWriter, r *http.Request, id string) {
	var payload struct {
		PlanID       string `json:"plan_id"`
		Confirmation string `json:"confirmation"`
	}
	if readJSON(r, &payload) != nil || payload.Confirmation != aiWorkflowPlanConfirmation {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "确认动态补丁方案需要显式确认"})
		return
	}
	experiment, err := s.loadExperiment(id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if experiment.Status != "planned" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "当前作业尚未生成待确认计划"})
		return
	}
	var plan aiWorkflowPlan
	planPath := filepath.Join(s.patchRoot(id), "workflow-ai", payload.PlanID, "plan.json")
	if err := readFileJSON(planPath, &plan); err != nil || plan.ID != payload.PlanID || plan.ExperimentID != id || plan.Status != "planned" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "动态补丁方案不存在或已失效"})
		return
	}
	if err := validateWorkflowAIPlan(plan, s.cfg.Workspace); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	updated, err := s.mutateExperiment(id, func(current *Experiment) error {
		params, ok := current.Metadata["workflow_params"].(map[string]any)
		if !ok {
			return errors.New("作业参数不存在")
		}
		params["pid"] = plan.PID
		if plan.Workflow == "memory_patch" {
			params["address"] = plan.Address
			params["expected_hex"] = plan.ExpectedHex
			params["data_hex"] = plan.DataHex
		}
		if plan.Workflow == "process_injection" {
			params["dll_path"] = plan.DLLPath
			params["declared_dll_path"] = plan.DLLPath
			params["method"] = plan.Method
		}
		params["plan_status"] = "confirmed"
		params["plan_id"] = plan.ID
		current.Metadata["workflow_params"] = params
		current.Metadata["workflow_ai_plan"] = map[string]any{"id": plan.ID, "status": "confirmed", "confirmed_at": now()}
		*current = s.status(*current, "queued", "AI 补丁方案已确认，等待执行确认")
		return nil
	})
	if err != nil {
		respond(w, nil, err)
		return
	}
	s.appendEvent(id, "workflow_ai_plan_confirmed", "queued", "人工已确认动态补丁方案，允许进入执行确认", map[string]any{"plan_id": plan.ID})
	writeJSON(w, http.StatusOK, map[string]any{"experiment": updated, "plan": plan})
}

func (s *Server) createAIPatchPlan(ctx context.Context, id, project, instruction, target, mode string) (aiPatchPlan, error) {
	profile, fallback := s.selectProvider("")
	if profile.Kind == "local" || !s.providerReady(profile) {
		return aiPatchPlan{}, errors.New("没有可用的大模型服务，请先在模型服务管理中完成连接测试")
	}
	files, contents, err := collectPatchSources(project, target)
	if err != nil {
		return aiPatchPlan{}, err
	}
	requestContext := map[string]any{"instruction": strings.TrimSpace(instruction), "requested_mode": mode, "target_hint": target, "project_files": files, "source_files": contents, "rules": []string{"优先修改源码", "只能选择 project_files 中的路径", "after 必须是完整文件内容", "证据不足时使用 needs_evidence，不得猜测偏移或代码"}}
	modelResult, usage, err := invokeAIPatchProvider(ctx, profile, requestContext)
	s.recordProviderUsage(profile.Name, 1, err != nil, usageTokens(usage, "input_tokens"), usageTokens(usage, "output_tokens"))
	if err != nil {
		return aiPatchPlan{}, err
	}
	if modelResult.NeedsEvidence != "" {
		return aiPatchPlan{}, fmt.Errorf("模型需要更多证据：%s", modelResult.NeedsEvidence)
	}
	if modelResult.Mode != "source_edit" || len(modelResult.Changes) == 0 {
		return aiPatchPlan{}, errors.New("模型没有生成可审查的源码修改")
	}
	plan := aiPatchPlan{ID: newID(), ExperimentID: id, Status: "planned", Mode: "source_edit", Instruction: strings.TrimSpace(instruction), Summary: modelResult.Summary, Evidence: modelResult.Evidence, Validation: modelResult.Validation, Risks: modelResult.Risks, Provider: profile.Name, Model: profile.Model, CreatedAt: now(), UpdatedAt: now()}
	seen := map[string]bool{}
	for _, change := range modelResult.Changes {
		path, pathErr := safeProjectFile(project, change.Path)
		if pathErr != nil || !sourceEditable(change.Path) || seen[change.Path] {
			return aiPatchPlan{}, errors.New("模型返回了无效或重复的源码路径")
		}
		seen[change.Path] = true
		before, readErr := os.ReadFile(path)
		if readErr != nil || len(change.After) == 0 || len(change.After) > 2<<20 {
			return aiPatchPlan{}, errors.New("模型返回的源码内容无效或超过 2MB")
		}
		plan.Changes = append(plan.Changes, aiSourceChange{Path: filepath.ToSlash(change.Path), BeforeSHA256: sha256Hex(before), Before: string(before), After: change.After, Reason: change.Reason})
	}
	root := filepath.Join(s.patchRoot(id), "ai", plan.ID)
	if err = os.MkdirAll(root, 0700); err != nil {
		return aiPatchPlan{}, err
	}
	if err = writeFileJSON(filepath.Join(root, "plan.json"), plan); err != nil {
		return aiPatchPlan{}, err
	}
	s.appendEvent(id, "ai_patch_planned", "completed", "大模型已生成可审查的源码修改方案", map[string]any{"plan_id": plan.ID, "files": len(plan.Changes), "provider": profile.Name, "model": profile.Model, "provider_fallback": fallback})
	return plan, nil
}

func collectPatchSources(project, target string) ([]string, map[string]string, error) {
	paths := []string{}
	_ = filepath.Walk(project, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !sourceEditable(path) || strings.Contains(filepath.ToSlash(path), "/.build/") || info.Size() > 256<<10 {
			return nil
		}
		rel, _ := filepath.Rel(project, path)
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(paths)
	if target != "" {
		clean := filepath.ToSlash(filepath.Clean(target))
		for i, path := range paths {
			if path == clean {
				paths = append([]string{path}, append(paths[:i], paths[i+1:]...)...)
				break
			}
		}
	}
	contents := map[string]string{}
	selected := []string{}
	total := 0
	for _, rel := range paths {
		if len(contents) >= 40 || total >= 768<<10 {
			break
		}
		path, err := safeProjectFile(project, rel)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || total+len(data) > 768<<10 {
			continue
		}
		contents[rel] = string(data)
		selected = append(selected, rel)
		total += len(data)
	}
	if len(contents) == 0 {
		return nil, nil, errors.New("源码工程中没有可供模型修改的文本源码")
	}
	return selected, contents, nil
}

func (s *Server) loadAIPlan(id, planID string) (aiPatchPlan, string, error) {
	if len(planID) != 32 {
		return aiPatchPlan{}, "", errors.New("无效的修改方案编号")
	}
	root := filepath.Join(s.patchRoot(id), "ai", planID)
	var plan aiPatchPlan
	err := readFileJSON(filepath.Join(root, "plan.json"), &plan)
	if err != nil || plan.ID != planID || plan.ExperimentID != id {
		return aiPatchPlan{}, "", errors.New("修改方案不存在")
	}
	return plan, root, nil
}

func (s *Server) applyAIPatchPlan(id, project, planID string) (aiPatchPlan, error) {
	plan, root, err := s.loadAIPlan(id, planID)
	if err != nil {
		return plan, err
	}
	if plan.Status != "planned" {
		return plan, errors.New("只有待应用的方案可以执行")
	}
	backup := filepath.Join(root, "backup")
	if err = os.MkdirAll(backup, 0700); err != nil {
		return plan, err
	}
	for _, change := range plan.Changes {
		path, pathErr := safeProjectFile(project, change.Path)
		if pathErr != nil {
			return plan, pathErr
		}
		current, readErr := os.ReadFile(path)
		if readErr != nil || sha256Hex(current) != change.BeforeSHA256 {
			return plan, fmt.Errorf("文件 %s 已发生变化，请重新生成方案", change.Path)
		}
	}
	for _, change := range plan.Changes {
		path, _ := safeProjectFile(project, change.Path)
		backupPath, _ := safeProjectFile(backup, change.Path)
		if err = os.MkdirAll(filepath.Dir(backupPath), 0700); err == nil {
			err = os.WriteFile(backupPath, []byte(change.Before), 0600)
		}
		if err == nil {
			err = os.WriteFile(path, []byte(change.After), 0600)
		}
		if err != nil {
			_, _ = s.rollbackAIPatchPlanFiles(project, root, plan)
			return plan, err
		}
	}
	plan.Status, plan.UpdatedAt = "applied", now()
	_ = writeFileJSON(filepath.Join(root, "plan.json"), plan)
	s.appendEvent(id, "ai_patch_applied", "completed", "已将模型源码修改写入重构工程", map[string]any{"plan_id": plan.ID, "files": len(plan.Changes)})
	return plan, nil
}

func (s *Server) rollbackAIPatchPlan(id, project, planID string) (aiPatchPlan, error) {
	plan, root, err := s.loadAIPlan(id, planID)
	if err != nil {
		return plan, err
	}
	if plan.Status != "applied" {
		return plan, errors.New("只有已应用的方案可以回滚")
	}
	plan, err = s.rollbackAIPatchPlanFiles(project, root, plan)
	if err != nil {
		return plan, err
	}
	plan.Status, plan.UpdatedAt = "rolled_back", now()
	_ = writeFileJSON(filepath.Join(root, "plan.json"), plan)
	s.appendEvent(id, "ai_patch_rolled_back", "completed", "已恢复模型修改前的源码", map[string]any{"plan_id": plan.ID})
	return plan, nil
}

func (s *Server) rollbackAIPatchPlanFiles(project, root string, plan aiPatchPlan) (aiPatchPlan, error) {
	for _, change := range plan.Changes {
		path, err := safeProjectFile(project, change.Path)
		if err != nil {
			return plan, err
		}
		backup, err := safeProjectFile(filepath.Join(root, "backup"), change.Path)
		if err != nil {
			return plan, err
		}
		data, err := os.ReadFile(backup)
		if err != nil {
			return plan, err
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func invokeAIPatchProvider(ctx context.Context, profile providerProfile, input any) (aiPatchModelResult, map[string]any, error) {
	schema := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"mode", "summary", "evidence", "source_changes", "validation", "risks", "needs_evidence"}, "properties": map[string]any{
		"mode": map[string]any{"type": "string", "enum": []string{"source_edit", "needs_evidence"}}, "summary": map[string]any{"type": "string"}, "evidence": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"source_changes": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"path", "after", "reason"}, "properties": map[string]any{"path": map[string]any{"type": "string"}, "after": map[string]any{"type": "string"}, "reason": map[string]any{"type": "string"}}}},
		"validation":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "risks": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "needs_evidence": map[string]any{"type": "string"}}}
	instructions := "你是授权逆向重构工程的源码修改代理。根据用户中文指令和实际源码生成最小、可编译的修改。只返回 JSON。路径必须来自 project_files；after 必须是完整文件内容。信息不足时 mode=needs_evidence 并说明缺少什么，严禁猜测。"
	rawInput, _ := json.Marshal(input)
	protocol := normalizeProviderProtocol(profile.Protocol, profile.Model)
	endpoint := strings.TrimRight(profile.BaseURL, "/") + "/chat/completions"
	payload := map[string]any{"model": profile.Model, "temperature": 0, "max_tokens": 16384, "response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "source_patch_plan", "strict": true, "schema": schema}}, "messages": []map[string]string{{"role": "system", "content": instructions}, {"role": "user", "content": string(rawInput)}}}
	if protocol == "responses" {
		endpoint = strings.TrimRight(profile.BaseURL, "/") + "/responses"
		payload = map[string]any{"model": profile.Model, "instructions": instructions, "input": string(rawInput), "max_output_tokens": 16384, "text": map[string]any{"format": map[string]any{"type": "json_schema", "name": "source_patch_plan", "strict": true, "schema": schema}}}
	}
	body, _ := json.Marshal(payload)
	keys := providerAPIKeys(profile)
	failures := []string{}
	for _, key := range keys {
		requestCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		req, _ := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			cancel()
			failures = append(failures, err.Error())
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, providerBrokerMaxBytes+1))
		resp.Body.Close()
		cancel()
		if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			failures = append(failures, fmt.Sprintf("HTTP %d", resp.StatusCode))
			continue
		}
		var envelope struct {
			OutputText string `json:"output_text"`
			Output     []struct {
				Content []struct{ Type, Text string } `json:"content"`
			} `json:"output"`
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Usage map[string]any `json:"usage"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			failures = append(failures, "响应不是 JSON")
			continue
		}
		content := envelope.OutputText
		for _, out := range envelope.Output {
			for _, item := range out.Content {
				if item.Type == "output_text" && content == "" {
					content = item.Text
				}
			}
		}
		if content == "" && len(envelope.Choices) > 0 {
			content = envelope.Choices[0].Message.Content
		}
		var result aiPatchModelResult
		if json.Unmarshal([]byte(content), &result) != nil {
			failures = append(failures, "模型结果不符合结构")
			continue
		}
		return result, envelope.Usage, nil
	}
	return aiPatchModelResult{}, nil, fmt.Errorf("模型服务调用失败：%s", strings.Join(failures, "; "))
}

func invokeAIWorkflowProvider(ctx context.Context, profile providerProfile, input any) (aiWorkflowModelResult, map[string]any, error) {
	schema := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"summary", "target_identity", "location_basis", "pid", "address", "expected_hex", "data_hex", "dll_path", "method", "module_source", "evidence", "validation", "risks", "rollback"}, "properties": map[string]any{
		"summary": map[string]any{"type": "string"}, "target_identity": map[string]any{"type": "string"}, "location_basis": map[string]any{"type": "string"}, "pid": map[string]any{"type": "integer"}, "address": map[string]any{"type": "string"}, "expected_hex": map[string]any{"type": "string"}, "data_hex": map[string]any{"type": "string"}, "dll_path": map[string]any{"type": "string"}, "method": map[string]any{"type": "string"}, "module_source": map[string]any{"type": "string"},
		"evidence": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "validation": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "risks": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "rollback": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}}
	instructions := "你是授权本地逆向补丁规划代理。根据用户意图和目标证据生成结构化 JSON 方案。只能面向明确授权的本地目标；必须说明目标身份、定位依据、证据、验证和回滚。memory_patch 必须返回 PID、地址、expected_hex、data_hex；process_injection 只能返回工作区内 DLL 的 load_library 方案。证据不足时不要猜测，返回空底层字段并在 risks 或 evidence 中说明不足。"
	rawInput, _ := json.Marshal(input)
	protocol := normalizeProviderProtocol(profile.Protocol, profile.Model)
	endpoint := strings.TrimRight(profile.BaseURL, "/") + "/chat/completions"
	payload := map[string]any{"model": profile.Model, "temperature": 0, "max_tokens": 8192, "response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "workflow_patch_plan", "strict": true, "schema": schema}}, "messages": []map[string]string{{"role": "system", "content": instructions}, {"role": "user", "content": string(rawInput)}}}
	if protocol == "responses" {
		endpoint = strings.TrimRight(profile.BaseURL, "/") + "/responses"
		payload = map[string]any{"model": profile.Model, "instructions": instructions, "input": string(rawInput), "max_output_tokens": 8192, "text": map[string]any{"format": map[string]any{"type": "json_schema", "name": "workflow_patch_plan", "strict": true, "schema": schema}}}
	}
	body, _ := json.Marshal(payload)
	failures := []string{}
	for _, key := range providerAPIKeys(profile) {
		requestCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			cancel()
			return aiWorkflowModelResult{}, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			cancel()
			failures = append(failures, err.Error())
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, providerBrokerMaxBytes+1))
		resp.Body.Close()
		cancel()
		if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			failures = append(failures, fmt.Sprintf("HTTP %d", resp.StatusCode))
			continue
		}
		var envelope struct {
			OutputText string `json:"output_text"`
			Output     []struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Usage map[string]any `json:"usage"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			failures = append(failures, "响应不是 JSON")
			continue
		}
		content := envelope.OutputText
		for _, output := range envelope.Output {
			for _, item := range output.Content {
				if item.Type == "output_text" && content == "" {
					content = item.Text
				}
			}
		}
		if content == "" && len(envelope.Choices) > 0 {
			content = envelope.Choices[0].Message.Content
		}
		var result aiWorkflowModelResult
		if json.Unmarshal([]byte(content), &result) != nil {
			failures = append(failures, "模型结果不符合结构")
			continue
		}
		return result, envelope.Usage, nil
	}
	return aiWorkflowModelResult{}, nil, fmt.Errorf("模型服务调用失败：%s", strings.Join(failures, "; "))
}

func usageTokens(usage map[string]any, key string) int64 {
	if usage == nil {
		return 0
	}
	if v, ok := usage[key].(float64); ok {
		return int64(v)
	}
	return 0
}
