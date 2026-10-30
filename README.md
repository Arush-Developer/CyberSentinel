# CyberSentinel X

JAI 2026, Track 1: Agentic AI for Cybersecurity. A multi-agent system that classifies network flows,
scores them for anomalies independently, looks for patterns across flows, investigates suspicious
ones with real tools, and makes explainable **simulated** ALLOW / BLOCK / REVIEW decisions.

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

Rebuild every model and report from the ZIP (about 7 minutes on a 10-core laptop):

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

Run the tests:

```bash
.venv/bin/python -m pytest -q
```

Start a replay from the Replay Lab screen, or from the command line:

```bash
curl -X POST localhost:8000/api/replay/start -H 'Content-Type: application/json' -d '{"speed": 2000}'
```

Score the hidden set when it is released (no submission is made):

```bash
.venv/bin/python scripts/score_records.py --input PATH/TO/hidden.parquet --output data/processed/hidden_predictions.parquet
```

## How it works

```
                 ┌─ Agent 1: CatBoost, 5 classes ──────────┐
 flow features ──┤                                         ├─► Agent 3: evidence fusion ─► simulated policy
                 └─ Agent 2: Isolation Forest, benign-only ┤     final_class                ALLOW / BLOCK / REVIEW
                                                           │     evidence_status
 flow order and ─► Campaign engine: cross-flow hypotheses ─┤     rationale
 metadata                                                  │
 triggers ───────► Investigation: bounded tool calls ──────┘
```

- **Agent 1** ([threat_agent.py](backend/agents/threat_agent.py)): best of four candidates on an internal
  holdout, with balanced class weights. Returns class, confidence and probabilities.
- **Agent 2** ([anomaly_agent.py](backend/agents/anomaly_agent.py)): trained on benign flows only, with
  its own preprocessing. Its score is a percentile among held-out benign flows, **not a probability**.
- **Agent 3** ([fusion_agent.py](backend/agents/fusion_agent.py)): keeps evidence types separate instead
  of averaging them, and returns `final_class`, `evidence_status` and a rationale built from measured values.
- **Campaign engine** ([campaign_engine.py](backend/intelligence/campaign_engine.py)): never reads labels or Agent 1's output.
- **Investigation** ([investigation_orchestrator.py](backend/agents/investigation_orchestrator.py)):
  deterministic planner, eight registered tools, at most three actions per flow, with timeouts, cancellation and audit logging. No LLM is used.
- **Policy** ([policy_engine.py](backend/policy/policy_engine.py)): configurable thresholds and a what-if mode.
- **Replay** ([replay_engine.py](backend/replay/replay_engine.py)): real records and real batch inference, with a global stop.

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
  as `VOLUMETRIC_CANDIDATE`, and record order standing in for time. **Endpoint-mode detectors have only
  been tested on synthetic fixtures**, and their thresholds may need adjusting on real hidden data.
- **Level 1 submission is not done.** The API details are in the event WhatsApp group, not in this
  repository. See [docs/LEVEL1_SUMMARY.md](docs/LEVEL1_SUMMARY.md).
- **Agent 2 barely sees brute force or port scans,** so many of those decisions rest on the classifier alone or on campaign context.
- **Benign review load is 13.3%** with campaigns on, mostly benign flows that share a port and window with an attack.
- **Replay investigations** use the whole-set campaign record for context, so a campaign's flow count can include later windows. Investigations are capped at 5 per replay batch by default.
- **`POST /api/flows/analyse`** assesses one flow with no cross-flow context.
- **Audit log and policy history** are held in memory and reset when the backend restarts. Replay position and results are saved.

## Disclosure

- **AI assistance:** this codebase was generated with Claude Code (Anthropic) from the team's engineering brief. Each team member must still review, test and understand their modules: see [docs/TEAM_HANDOFF.md](docs/TEAM_HANDOFF.md).
- **Data:** organiser-provided CICIDS2017 pack only. Unit tests use synthetic fixtures, labelled as such.
- **Third-party components:** scikit-learn, CatBoost, pandas, NumPy, PyArrow, FastAPI, Uvicorn, Pydantic, React, Vite, Tailwind CSS, Recharts, React Flow (`@xyflow/react`), Lucide.
- **Credentials:** none are stored. The submission adapter reads any token from an environment variable.

## Documentation

- [API reference](docs/API.md)
- [Team ownership](docs/TEAM_OWNERSHIP.md)
- [Team handoff](docs/TEAM_HANDOFF.md)
- [Module contracts](docs/MODULE_CONTRACTS.md)
- [Integration guide](docs/INTEGRATION_GUIDE.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Level 1 summary](docs/LEVEL1_SUMMARY.md)
