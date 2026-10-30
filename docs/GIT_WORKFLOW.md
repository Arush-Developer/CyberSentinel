# Git workflow

**Current state:** `main` has two commits by Arush-Developer (`646744a demo`, `1e52673 upd1`) and is pushed to `origin`. The repair work described in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) is **uncommitted in the working tree**. No commits, branches, tags or pushes were made for you.

## Rules

- Commit only your own work, under your own identity. Do not set `--author` or change `user.name` to record someone else.
- Do not backdate commits, and do not split generated code into commits under teammates' names. The rulebook asks for honest history.
- A teammate's commit should be something they actually reviewed, tested or changed.
- AI assistance is disclosed in the README. Keep the `Co-Authored-By` line on commits that contain generated code.
- Before every commit, run `git status` and check that no data, models, `configs/submission.yaml` or tokens are staged.

## 1. Preserve the Day 1 checkpoint (Arush)

Do this first. It marks the state before the repair.

```bash
git tag day1-checkpoint 1e52673
```
```bash
git push origin day1-checkpoint
```

## 2. Commit the repair (Arush)

These commits follow file dependencies. Each one should pass `.venv/bin/python -m pytest -q` only once the last backend commit is in, because the contracts, agents and tests were repaired together. Run the suite before pushing.

**Commit 1: shared contracts and data foundations**

```bash
git add backend/schemas/contracts.py backend/preprocessing/data_processor.py backend/investigation/audit.py backend/investigation/tools.py backend/intelligence/campaign_engine.py backend/intelligence/evidence_engine.py configs/default.yaml
```
```bash
git commit -m "Honour supplied replay order, add causal evidence and SQLite audit" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Commit 2: Agent 3 evidence statuses**

```bash
git add backend/agents/fusion_agent.py backend/policy/policy_engine.py backend/services/model_service.py
```
```bash
git commit -m "Align Agent 3 evidence statuses with the brief" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Commit 3: Agents 4 and 5, Level 2 export**

```bash
git add backend/agents/temporal_agent.py backend/agents/defense_agent.py backend/services/level2.py scripts/run_level2.py scripts/rehearse_level2.py
```
```bash
git commit -m "Add temporal correlation and adaptive defence agents with Level 2 export" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Commit 4: replay and API integration**

```bash
git add backend/replay/replay_engine.py backend/services/app_state.py backend/api/routes.py
```
```bash
git commit -m "Run all five agents in live replay and expose them through the API" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Commit 5: evaluation and reports**

```bash
git add scripts/evaluate.py scripts/profile_dataset.py scripts/run_all.sh data/reports
```
```bash
git commit -m "Report evaluation modes A to C and correct the Level 1 summary" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Commit 6: backend tests**

```bash
git add tests pytest.ini
```
```bash
git commit -m "Test agents 4 and 5, causality, tools and saved models on real records" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Commit 7: website and browser tests**

```bash
git add frontend/src frontend/e2e frontend/index.html frontend/package.json frontend/package-lock.json frontend/playwright.config.ts
```
```bash
git commit -m "Show agents 3 to 5 and evaluation modes; add Chrome tests" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Commit 8: documentation**

```bash
git add README.md docs
```
```bash
git commit -m "Add codebase audit, status and Git workflow; update docs" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Then check that nothing was missed, and push:

```bash
git status
```
```bash
git push origin main
```

## 3. Team branches

Each member creates their branch from the updated `main`, after step 2.

| Member | Branch | Create it with |
|---|---|---|
| Arush | `feature/backend-arush` | `git switch -c feature/backend-arush` |
| Arpit | `feature/ml-arpit` | `git switch -c feature/ml-arpit` |
| Arnav | `feature/intelligence-arnav` | `git switch -c feature/intelligence-arnav` |
| Lucky | `feature/frontend-lucky` | `git switch -c feature/frontend-lucky` |
| Agrim | `feature/frontend-agrim` | `git switch -c feature/frontend-agrim` |

Each member works through their section of [TEAM_HANDOFF.md](TEAM_HANDOFF.md), tests their modules, and commits what they really changed, for example:

```bash
git add <the files you changed>
```
```bash
git commit -m "Describe what you changed and why"
```
```bash
git push -u origin <your branch>
```

Open a pull request into `main`. If a review finds nothing to change, record that in the pull request rather than making an empty commit.

## 4. Milestones against the brief's suggested sequence

| Milestones | Where the work is |
|---|---|
| 1 to 8: contracts, data, Agents 1 to 3 | `646744a`, plus repair commits 1, 2 and 5 |
| 9 to 13: campaigns, tools, orchestration, policy, replay, API | `646744a`, plus repair commits 1 and 4 |
| Level 2 Agents 4 and 5 (not in the suggested list) | Repair commits 3 and 4 |
| 14 to 18: frontend | `646744a`, plus repair commit 7 |
| 19 and 20: tests and verification | Repair commits 6 and 7 |

The earlier history cannot honestly be re-split into these milestones, because it was committed in one piece. Leave it as it is.
