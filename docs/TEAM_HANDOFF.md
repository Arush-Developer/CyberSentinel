# Team handoff

Every member must be able to explain their modules. Work through your section: read the code, run the commands, and be ready for the questions. Your own improvements go in as your own commits.

Setup for everyone is in the [README](../README.md#quick-start).

## First: Git (Arush)

The folder is not yet a Git repository, and nothing has been committed for you. History should show what actually happened, so don't split this generated code into commits under other people's names. A single first commit with an honest message is the accurate record. Check the staged list contains no data, models or credentials before committing.

```bash
git init
```
```bash
git add .
```
```bash
git status
```
```bash
git commit -m "Initial integrated system generated with Claude Code from team brief"
```

After Level 1 is submitted, keep the Day 1 checkpoint:

```bash
git tag day1-final
```

## Arush: architecture and backend

**Files:** see [TEAM_OWNERSHIP.md](TEAM_OWNERSHIP.md).

```bash
.venv/bin/python -m pytest tests/test_fusion_policy.py tests/test_api_replay.py -v
```
```bash
.venv/bin/python scripts/calibrate_fusion.py
```

**Do next:** submit Level 1 ([LEVEL1_SUMMARY.md](LEVEL1_SUMMARY.md)). Read the Level 2 briefing.

**Be ready to explain:** why evidence types aren't averaged; why fusion leaves `final_class` alone; what the ablation table shows; how Stop reaches a running investigation; why decisions are simulated only.

## Arpit: data and supervised ML

```bash
.venv/bin/python scripts/profile_dataset.py
```
```bash
.venv/bin/python scripts/train_models.py
```
```bash
.venv/bin/python scripts/leakage_audit.py
```
```bash
.venv/bin/python -m pytest tests/test_preprocessing.py -v
```

**Do next:** look at the 6 misclassified validation flows in `data/processed/eval_predictions.parquet`. Investigate why DoS recall falls to 0.981 on the record-order split, since it's the best available clue about generalisation.

**Be ready to explain:** why the score is so high and why that isn't leakage; why `record_id` and `Destination Port` are out; why splits are grouped; what temperature scaling did and that it can't change the predicted class.

## Arnav: anomaly and campaigns

```bash
.venv/bin/python -m pytest tests/test_campaign_investigation.py tests/test_submission_and_agents.py -v
```

Then inspect `agent2` and `campaign_intelligence` in `data/reports/evaluation_report.json`.

**Do next:** Agent 2 almost never flags brute force or port scans, which is its biggest weakness. Try improving it, selecting on internal splits only. `robust_deviation` got 0 recall at its threshold, probably because many benign flows hit the z-score cap and tie; that's worth fixing. Check endpoint-mode thresholds on the hidden set's metadata when it arrives.

**Be ready to explain:** what the anomaly score means and why it isn't a probability; how Agent 2 stays independent; what cohort mode can't claim; why brute-force records are only behavioural indicators; why 12.7% of volumetric campaign members are benign.

## Lucky: frontend foundation

```bash
npm --prefix frontend run dev
```
```bash
npm --prefix frontend run build
```

With the backend running, check the Command Centre and Replay Lab. Start, pause, resume and stop a replay, and confirm the sidebar STOP works from any screen. Check narrow widths.

**Do next:** there are no automated frontend tests, so adding some would help. Review keyboard use and the mobile layout.

**Be ready to explain:** how the SSE stream reaches the page and why rendering is throttled; why counts come from polling rather than the feed; how the page behaves when the backend is down.

## Agrim: intelligence screens

With the backend running, go through Attack Intelligence, Investigation Workbench, Model Intelligence, and Defence & Audit. Simulate a threshold change, then apply and reset it, and confirm it appears in the audit log.

**Do next:** the evidence graph layout is a simple column layout, and labels get small on busy flows. The Attack Intelligence graph will need rework when endpoint metadata arrives, to show sources and destinations.

**Be ready to explain:** how the graph is built from real output; why the confusion matrix uses log shading; what the what-if mode does and doesn't change; why the screen warns that scores may not generalise.

## Open questions for Arush

1. **Official submission API:** endpoint, auth and payload format.
2. **Level 2 briefing:** due in the 6:00 to 8:00 PM slot.
3. **Rule sheet wording:** the Day 1 heading says "Build Two Agents" but its table lists three. All three are built.
