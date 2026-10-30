# Implementation status

Last verified on 30 October 2026. **WORKING** means the code was executed against the real models and official records, unless the row says otherwise. Owners are responsible for review; they did not necessarily write the code. See the disclosure in the [README](../README.md#disclosure).

Test files are under `tests/`, and no test failed in the final runs.

| Module | Owner | Files implemented | Files repaired | Actual functionality | Tests executed | Passed | Failed | Remaining blockers | Status |
|---|---|---|---|---|---:|---:|---:|---|---|
| Dataset and profiling | Arpit | `dataset_profile.md` | `scripts/profile_dataset.py` | Safe extraction, full profile, misleading features | Part of 45 in `agents/` | All | 0 | None | WORKING |
| Preprocessing | Arpit | | `data_processor.py` | Column and label standardising, medians for bad values, training-only fit, supplied replay order, any flow file | Part of 45 | All | 0 | None | WORKING |
| Agent 1: threat detection | Arpit | | None needed | CatBoost, five classes. Reproduced by separate code | Part of 45 | All | 0 | None | WORKING |
| Agent 2: anomaly | Arnav | | None needed | Benign-only Isolation Forest, percentile score, measured evidence | Part of 45 | All | 0 | Barely detects brute force and port scans | WORKING |
| Agent 3: fusion | Arush | | `fusion_agent.py` | The brief's five conditions, kept apart from campaign evidence | Part of 45 | All | 0 | None | WORKING |
| Agent 4: temporal correlation | Arnav | `temporal_agent.py` | | Causal source and destination groups in a sliding window | Part of 45, and 22 integration | All | 0 | Real endpoints not available yet | TESTED: real flows, invented endpoints |
| Agent 5: adaptive defence | Arush | `defense_agent.py` | | Temporary `SOURCE_IP` policies, activation and expiry logs | Part of 45, and 22 integration | All | 0 | Thresholds are untuned defaults | TESTED: real flows, invented endpoints |
| Level 2 export | Arush | `services/level2.py`, `run_level2.py`, `rehearse_level2.py` | | Three CSVs, rule checker | Part of 22 integration | All | 0 | Column names to confirm; upload API unknown | BLOCKED for upload; export TESTED |
| Campaign intelligence | Arnav | | `campaign_engine.py` | Cohort mode on the pack; endpoint mode | 8 `intelligence/` | All | 0 | Endpoint mode has no real-data measurement | WORKING in cohort mode; TESTED in endpoint mode |
| Investigation | Arnav, Arush | | `tools.py` | Eight tools, planner, budget, timeouts, cancel, logging | 17 `investigation/` | All | 0 | Source and destination tools are unavailable on the pack, and say so | WORKING |
| Policy and what-if | Arush | | `policy_engine.py` | Thresholds, history, simulation | 7 `policy/` | All | 0 | None | WORKING |
| Audit | Arush | | `audit.py` | SQLite log that survives restarts | Part of 6 `replay/` and 17 `investigation/` | All | 0 | None | WORKING |
| Replay | Arush | | `replay_engine.py` | Start, pause, resume, stop, restore; real SSE | 6 `replay/`, 12 browser | All | 0 | None | WORKING |
| API | Arush | | `routes.py`, `contracts.py`, `app_state.py` | Typed REST and SSE on the real pipeline | 32 `api/` | All | 0 | None | WORKING |
| Level 1 submission | Arush | | `level1_summary.json` | Payload ready; adapter refuses until configured | 2 in `api/` | All | 0 | **API details are only in the WhatsApp group** | BLOCKED |
| Frontend: six pages | Lucky, Agrim | `CorrelationGroups.tsx`, `AdaptiveDefense.tsx`, `ReplayInputNotice.tsx`, `e2e/app.spec.ts` | Listed in `CODEBASE_AUDIT.md` | Every page reads the backend | 12 in Chrome on each of two inputs; typecheck; build | All | 0 | Bundle-size warning only | WORKING |

**Other checks:**

- `tests/test_imports.py`: 44 tests. Every backend module and script imports, and the required routes exist.
- **Total:** 181 Python tests and 24 browser test runs passed.

## Verification runs

| Check | Result |
|---|---|
| Rebuild from the ZIP into a separate folder, using `scripts/run_all.sh` | Failed at first, finding a bug in `calibrate_fusion.py`. Fixed. The rebuild then gave an **identical** `level1_summary.json` and `level2_rehearsal.json`, and left `configs/calibrated.json` and `configs/campaign_baseline.json` unchanged. Model files differ in bytes but give the same results |
| Documented startup, on ports 8000 and 5173 | Clean. Backend ready in about 6 seconds |
| Complete replay through the API | 114,185 flows, status completed, counts match the report. SSE delivered flow, campaign, investigation and state events |
| Causality | Cutting the stream or scrambling later records leaves all earlier decisions unchanged |
| Replay against export | The same actions and policies, record by record |

## Evaluation, official validation records

114,185 records, which were not used for training or tuning.

| Mode | Accuracy | Macro-F1 | False-positive rate | False-negative rate | Agreement | Allow | Block | Review |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A: classifier alone | 0.99995 | 0.99982 | 0.0050% | 0.0055% | n/a | 59,995 | 54,166 | 24 |
| B: + anomaly and fusion | 0.99995 | 0.99982 | 0.0050% | 0.0055% | 76.4% | 56,997 | 54,168 | 3,020 |
| C: complete, batch | 0.99995 | 0.99982 | 0.0050% | 0.0055% | 76.4% | 52,039 | 54,141 | 8,005 |
| C: complete, causal replay | 0.99995 | 0.99982 | not separately reported | not separately reported | 76.4% | 52,008 | 54,141 | 8,036 |

The added layers do not improve classification. They add explanation and change how decisions are routed.

## Rehearsal, invented endpoints

From `data/reports/level2_rehearsal.json`: 164 policies, 99.26% of attack flows blocked, 0.54% of benign flows blocked (325), no rule violations. **The address assignment was made up, so this proves the mechanism and not the expected score.**
