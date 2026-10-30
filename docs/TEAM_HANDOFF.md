# Team handoff

Every member must be able to explain their modules. Work through your section: read the code, run the commands, and be ready for the questions. Your own improvements go in as your own commits.

Setup is in the [README](../README.md#quick-start). Exact file lists are in [TEAM_OWNERSHIP.md](TEAM_OWNERSHIP.md).

## Git workflow

See [GIT_WORKFLOW.md](GIT_WORKFLOW.md). Nothing has been committed for anyone.

## Arush: backend and integration

**Review first:** `services/model_service.py` (how everything is run), `agents/fusion_agent.py`, `policy/policy_engine.py`, `replay/replay_engine.py`, `schemas/contracts.py`.

```bash
.venv/bin/python -m pytest tests/agents/test_fusion.py tests/policy tests/replay tests/api tests/integration -v
```
```bash
.venv/bin/python scripts/calibrate_fusion.py
```

**Do next:** submit Level 1 ([LEVEL1_SUMMARY.md](LEVEL1_SUMMARY.md)). Read the Level 2 briefing.

**Understand before committing:** why evidence types aren't averaged; why fusion leaves `final_class` alone; what the ablation table shows; how Stop reaches a running investigation; why decisions are simulated only.

## Arpit: data and supervised ML

**Review first:** `preprocessing/data_processor.py`, `agents/threat_agent.py`, `scripts/train_models.py`, `data/reports/dataset_profile.json`, `data/reports/leakage_audit.json`.

```bash
.venv/bin/python -m pytest tests/agents/test_preprocessing.py tests/agents/test_agents.py -v
```
```bash
.venv/bin/python scripts/profile_dataset.py
```
```bash
.venv/bin/python scripts/leakage_audit.py
```

Retrain only with a reason, because it replaces the saved models:

```bash
.venv/bin/python scripts/train_models.py
```

**Do next:** look at the 6 misclassified validation flows in `data/processed/eval_predictions.parquet`. Investigate why DoS recall falls to 0.981 on the record-order split; it's the best available clue about generalisation.

**Understand before committing:** why the score is so high and why that isn't leakage; why `record_id` and `Destination Port` are out; why splits are grouped; what temperature scaling did and why it can't change the predicted class.

## Arnav: anomaly and security intelligence

**Review first:** `agents/anomaly_agent.py`, `intelligence/feature_explainer.py`, `intelligence/campaign_engine.py`, `investigation/tools.py`, `investigation/registry.py`. Then read `agent2` and `campaign_intelligence` in `data/reports/evaluation_report.json`.

```bash
.venv/bin/python -m pytest tests/intelligence tests/investigation tests/agents/test_agents.py -v
```

**Do next:** Agent 2 almost never flags brute force or port scans, which is its biggest weakness. Try improving it, selecting on internal splits only. `robust_deviation` got 0 recall at its threshold, probably because many benign flows hit the z-score cap and tie. Check endpoint-mode thresholds when the hidden set's metadata arrives.

**Understand before committing:** what the anomaly score means and why it isn't a probability; how Agent 2 stays independent; what cohort mode can't claim; why brute-force records are only behavioural indicators; why 12.7% of volumetric campaign members are benign; why `RobustBaseline` must stay importable from `anomaly_agent.py`.

## Lucky: frontend foundation

**Review first:** `app/router.tsx`, `components/Layout.tsx`, `services/api.ts`, `services/replay.ts`, `replay/ReplayLab.tsx`.

```bash
npm --prefix frontend run build
```
```bash
npm --prefix frontend run dev
```

With the backend running, check by hand: Command Centre shows agent cards and live counts; start, pause, resume and stop a replay; the top-bar STOP works from any screen; stop the backend and confirm the page says so; check a narrow window.

**Do next:** there are no automated frontend tests, so adding some would help. Review keyboard use.

**Understand before committing:** how the SSE stream reaches the page and why rendering is throttled; why counts come from polling rather than the feed; what `Layout` does while models load.

## Agrim: analytics and investigation

**Review first:** `analytics/ThreatAnalytics.tsx`, `analytics/ModelMetrics.tsx`, `investigations/InvestigationWorkbench.tsx`, `evidence-graph/EvidenceGraph.tsx`, `audit/PolicyControls.tsx`.

```bash
npm --prefix frontend run build
```

With the backend running, check by hand: Attack Intelligence shows the hypothesis, contradicting evidence and relationships; the Workbench shows real tool calls and the graph; Model Intelligence matches `data/reports/evaluation_report.json`; simulate a threshold change, apply it, confirm it in the audit log, then reset it.

**Do next:** the graph uses a simple column layout, and labels get small on busy flows. The campaign graph will need rework when endpoint metadata arrives, to show sources and destinations.

**Understand before committing:** how the graph is built from real output; why the confusion matrix uses log shading; what what-if mode does and doesn't change; why the screen warns that scores may not generalise.

## Open questions for Arush

1. **Official submission API:** endpoint, auth and payload format.
2. **Level 2 briefing:** due in the 6:00 to 8:00 PM slot.
3. **Rule sheet wording:** the Day 1 heading says "Build Two Agents" but its table lists three. All three are built.

## New since the first handoff

- **Arush:** explain `DefenseLoop.step` and why a flow can never be blocked by a policy its own evidence created. Explain why replay and the export read Agents 1 to 3 evidence only. Run `scripts/rehearse_level2.py`, then read `tests/integration/test_level2.py::test_future_records_cannot_change_earlier_decisions`.
- **Arnav:** explain `TemporalCorrelationAgent`, what a group is, and why anomaly-only groups never create a policy. Why does a source need a 60% attack share?
- **Agrim:** walk a judge from a policy on Defence & Audit to its group on Attack Intelligence and to a blocked flow in the Workbench.
- **Lucky:** run `npm --prefix frontend run test:e2e`, then explain what each browser test proves, and what it doesn't.
- **Everyone:** the panel will ask about false blocks. A shared source that mostly sends benign traffic is protected by the attack-share rule, but benign flows from a blocked source are still blocked while the policy is active. That is the containment trade-off.
