# CyberSentinel X

JAI 2026, Track 1: Agentic AI for Cybersecurity. A five-agent system that classifies network flows,
scores them for anomalies independently, correlates suspicious flows over time, investigates them with
real tools, and makes explainable **simulated** decisions, including temporary source-address policies.

This is an offline replay of the organisers' CICIDS2017 pack. It never touches a live network or firewall.

## Results on the official validation records

114,185 records. No model or threshold was tuned on them. Regenerate with `scripts/evaluate.py`;
full detail is in `data/reports/evaluation_report.json`.

| Metric | Value |
|---|---|
| Accuracy | 0.99995 |
| Macro-F1 | 0.99982 |
| Macro-F1, excluding 9,795 rows whose exact features also occur in training | 0.99981 |
| Balanced accuracy | 0.99969 |
| False-positive rate (benign called attack) | 0.0050% |
| False-negative rate (attack called benign) | 0.0055% |

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| BENIGN | 0.99995 | 0.99995 | 0.99995 | 60,001 |
| BRUTE_FORCE | 1.00000 | 0.99855 | 0.99928 | 1,384 |
| DOS | 0.99992 | 1.00000 | 0.99996 | 24,000 |
| DDOS | 1.00000 | 1.00000 | 1.00000 | 14,400 |
| PORT_SCAN | 0.99993 | 0.99993 | 0.99993 | 14,400 |

**Agent 2 (anomaly, benign-only Isolation Forest):** ROC-AUC 0.884, PR-AUC 0.826, recall 55.9% at a
5.0% false-positive rate. It flags 89% of DDoS and 73% of DoS flows, but only 0.07% of brute-force and
0.35% of port-scan flows, which look statistically normal to it.

**Agent agreement:** 76.4%. Most disagreement is Agent 1 calling brute force or port scans that Agent 2 finds normal.

**Agent 3 evidence status, Agents 1 to 3 only:** AGREED_BENIGN 57,000; MULTI_SIGNAL_ATTACK 30,290; CLASSIFIER_ONLY 23,893; ANOMALY_ONLY 3,001; UNCERTAIN 1.

**Agents 4 and 5 have no measured result on real endpoints,** because the pack has none. See [Known limitations](#known-limitations).

### How to read these numbers

- **The classifier score reflects this capture, not networks in general.** Each attack class here has
  almost constant TCP fingerprints. `Init_Win_bytes_forward` takes 1 to 4 distinct values per attack
  class, against 1,530 for benign. No single feature leaks the label: removing the 25 strongest still
  leaves macro-F1 at 0.9996 (`scripts/leakage_audit.py`). A harder split, fitting on early record IDs and
  testing on late ones, gives 0.9973 with DoS recall at 0.981.
- **Fusion does not improve classification.** `final_class` comes from Agent 1. The one override rule
  tested, promoting unsure BENIGN calls on flagged anomalies, failed internal validation and is off.
- **The extra layers trade review load for a little coverage:**

| Layers | Macro-F1 | Attacks auto-allowed | Attacks blocked | Benign sent to review |
|---|---:|---:|---:|---:|
| Agent 1 alone | 0.99982 | 3 | 99.97% | 0.01% |
| + Agent 2 | 0.99982 | 2 | 99.97% | 5.01% |
| + Campaign intelligence | 0.99982 | 1 | 99.92% | 13.27% |
| + Investigation | 0.99982 | 1 | 99.92% | 13.27% |

  Their value here is explanation and a second opinion rather than better scores. They may matter more
  on traffic the classifier has not seen, but that has not been measured.
- **Replay looks only backwards, and it barely changes the outcome.** Running the complete system as a forward-only replay gives the same macro-F1 and the same 54,141 blocks as the batch run, with 31 more flows sent to review. Modes A, B and C are in `evaluation_modes` in the report.

## Technology stack

- **Frontend:** React, TypeScript, Vite, Tailwind CSS, Recharts, React Flow, Lucide
- **Backend:** Python, FastAPI, Pydantic
- **ML:** CatBoost, scikit-learn, pandas, NumPy, PyArrow

## Quick start

Requires Python 3.12 and Node 20 or later. Put the organisers' ZIP at `data/raw/cyber-pack.zip`
(`data/raw/official_dataset.zip` also works).

```bash
/opt/homebrew/bin/python3.12 -m venv .venv
```
```bash
.venv/bin/pip install -r requirements.txt
```
```bash
npm --prefix frontend ci
```

To train: rebuild every model and report from the ZIP (about 7 minutes on a 10-core laptop). This also extracts the dataset, so run it once after cloning:

```bash
./scripts/run_all.sh
```

Start the backend on port 8000. Saved models load automatically; scoring the validation set takes a few seconds.

```bash
.venv/bin/uvicorn backend.main:app --port 8000
```

In a second terminal, start the dashboard, then open http://localhost:5173:

```bash
npm --prefix frontend run dev
```

API documentation is at http://localhost:8000/docs and in [docs/API.md](docs/API.md).

Run the tests:

```bash
.venv/bin/python -m pytest -q
```

Start a replay from the Replay Lab screen, where you can also pause, resume and stop it, or from the command line:

```bash
curl -X POST localhost:8000/api/replay/start -H 'Content-Type: application/json' -d '{"speed": 2000}'
```

Run the browser tests in your installed Chrome. They start their own backend and frontend on other ports. The second command also exercises Agents 4 and 5, on a file made by `./scripts/run_all.sh` or `scripts/rehearse_level2.py`:

```bash
npm --prefix frontend run test:e2e
```
```bash
E2E_REPLAY_INPUT="$PWD/data/processed/rehearsal/flows.parquet" npm --prefix frontend run test:e2e
```

When the hidden set is released, write the three Level 2 files. This uploads nothing, and fails if the files break the brief's rules:

```bash
.venv/bin/python scripts/run_level2.py --input PATH/TO/hidden.parquet --out-dir data/processed/level2
```

Show that run on the website:

```bash
CYBERSENTINEL_REPLAY_INPUT=PATH/TO/hidden.parquet .venv/bin/uvicorn backend.main:app --port 8000
```

## How it works

The layout and who owns each module are in [docs/TEAM_OWNERSHIP.md](docs/TEAM_OWNERSHIP.md).

```
                 ┌─ Agent 1: CatBoost, 5 classes ──────────┐
 flow features ──┤                                         ├─► Agent 3: evidence fusion ─► simulated policy
                 └─ Agent 2: Isolation Forest, benign-only ┤     final_class                ALLOW / BLOCK / REVIEW
                                                           │     evidence_status
 flow order and ─► Campaign engine: cross-flow hypotheses ─┤     rationale
 metadata                                                  │
 triggers ───────► Investigation: bounded tool calls ──────┘

 At each record, in order, with source and destination addresses:
   1. Agent 5 applies policies already active. A match is BLOCKED and not analysed.
   2. Otherwise ALLOW. Agent 4 adds the flow to its groups, and Agent 5 may activate a policy for LATER flows.
```

- **Agent 1** ([threat_agent.py](backend/agents/threat_agent.py)): best of four candidates on an internal
  holdout, with balanced class weights. Returns class, confidence and probabilities.
- **Agent 2** ([anomaly_agent.py](backend/agents/anomaly_agent.py)): trained on benign flows only, with
  its own preprocessing. Its score is a percentile among held-out benign flows, **not a probability**.
- **Agent 3** ([fusion_agent.py](backend/agents/fusion_agent.py)): keeps evidence types separate instead
  of averaging them, and returns `final_class`, `evidence_status` and a rationale built from measured values.
- **Agent 4** ([temporal_agent.py](backend/agents/temporal_agent.py)): groups suspicious flows by source, and
  by destination when several sources converge, inside a sliding window of records it has already seen.
- **Agent 5** ([defense_agent.py](backend/agents/defense_agent.py)): temporary simulated `SOURCE_IP` policies, based
  on repeated attack calls, Agent 2 support and attack share. Repeat offenders get longer policies.
- **Campaign engine** ([campaign_engine.py](backend/intelligence/campaign_engine.py)): never reads labels or Agent 1's output.
- **Investigation** ([investigation_orchestrator.py](backend/agents/investigation_orchestrator.py)):
  deterministic planner, eight registered tools, at most three actions per flow, with timeouts, cancellation and audit logging. No LLM is used.
- **Policy** ([policy_engine.py](backend/policy/policy_engine.py)): configurable thresholds and a what-if mode.
- **Replay** ([replay_engine.py](backend/replay/replay_engine.py)): real records in the supplied order and real batch
  inference, with a global stop. Its tools cannot see later records.
- **Audit** ([audit.py](backend/investigation/audit.py)): every tool call, control action and policy change, saved to SQLite.

## Key data decisions

- **Labels** are already the five benchmark classes in this pack, so the mapping in `configs/default.yaml`
  is an explicit identity. Any other label raises an error rather than being coerced.
- **Leakage:** `record_id` is never a model input, because its range differs by class. `Destination Port`
  was tested and dropped: it added no macro-F1, and it is near-deterministic for some classes here.
- **Splits:** training is split 70/15/15, with identical rows kept in the same split so they cannot inflate holdout scores.
- **Validation labels** are read only to score finished predictions. The organisers' README permits tuning
  on `eval/`; we chose not to, as the team brief requires.
- **Cleaning:** this pack has no missing or infinite values, but the pipeline handles them using training
  medians. It drops 3 constant and 4 duplicate columns.

## Known limitations

- **No endpoint metadata in this pack.** IPs, source port, protocol and sequence ship only with the hidden
  set. On this data the campaign engine runs in `cohort` mode: no source attribution, DoS and DDoS merged
  as `VOLUMETRIC_CANDIDATE`, and record order standing in for time. Agents 4 and 5 are off.
- **Agents 4 and 5, and endpoint-mode campaigns, are unmeasured on real endpoints.** They were tested on real
  flows with invented addresses. `data/reports/level2_rehearsal.json` proves the mechanism and the file rules. It
  does not predict the hidden-set score, and their thresholds are engineering defaults, not tuned values.
- **Level 1 submission is not done.** The API details are in the event WhatsApp group, not in this
  repository. See [docs/LEVEL1_SUMMARY.md](docs/LEVEL1_SUMMARY.md).
- **Level 2 upload is not built.** No API details exist yet. The `replay.csv` columns and two column spellings are
  inferred from an inconsistent table in the brief: see [docs/MODULE_CONTRACTS.md](docs/MODULE_CONTRACTS.md#level-2-files).
- **Agent 2 barely sees brute force or port scans,** so many of those decisions rest on the classifier alone or on campaign context.
- **Benign review load is 13.3%** with campaigns on, mostly benign flows that share a port and window with an attack.
- **Replay investigations** are capped at 5 per batch by default, so most triggered flows are not investigated in a live replay. The batch evaluation investigates all of them.
- **Replay campaigns** are assessed per batch, so a flow's campaign can depend on later flows in its own batch. Agents 4 and 5 do not read campaigns; they work record by record.
- **`POST /api/flows/analyse`** assesses one flow with no cross-flow context.
- **A replay of a separately supplied file** (`CYBERSENTINEL_REPLAY_INPUT`) is not saved across restarts, so it can't overwrite the official run. Its audit log is also held in memory.

## Disclosure

- **AI assistance:** this codebase was generated with Claude Code (Anthropic) from the team's engineering brief. Each team member must still review, test and understand their modules: see [docs/TEAM_HANDOFF.md](docs/TEAM_HANDOFF.md).
- **Data:** organiser-provided CICIDS2017 pack only. Unit tests use synthetic fixtures, labelled as such.
- **Third-party components:** scikit-learn, CatBoost, pandas, NumPy, PyArrow, FastAPI, Uvicorn, Pydantic, React, Vite, Tailwind CSS, Recharts, React Flow (`@xyflow/react`), Lucide, Playwright (tests only).
- **Synthetic data:** `scripts/rehearse_level2.py` and its tests attach invented addresses to real eval flows, and are labelled as such. No mock or hard-coded prediction is used anywhere.
- **Credentials:** none are stored. The submission adapter reads any token from an environment variable.

## Documentation

- [API reference](docs/API.md)
- [Team ownership](docs/TEAM_OWNERSHIP.md)
- [Team handoff](docs/TEAM_HANDOFF.md)
- [Module contracts](docs/MODULE_CONTRACTS.md)
- [Integration guide](docs/INTEGRATION_GUIDE.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Codebase audit](docs/CODEBASE_AUDIT.md)
- [Git workflow](docs/GIT_WORKFLOW.md)
- [Refactor audit, historic](docs/REFACTOR_AUDIT.md)
- [Level 1 summary](docs/LEVEL1_SUMMARY.md)
