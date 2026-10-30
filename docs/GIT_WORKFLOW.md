# Git workflow

**Current state:** `main` has four commits by Arush-Developer (`646744a demo`, `1e52673 upd1`, `cf88040 upd2`, `c8d8fd8 up3`), all pushed to `origin`. Most of the repair is in `upd2` and `up3`. A few fixes made after them are uncommitted: see step 2. No commits, branches, tags or pushes were made for you.

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

## 2. Commit the remaining fixes (Arush)

`origin/main` is missing a fix that matters: at `c8d8fd8`, `scripts/calibrate_fusion.py` still imports a renamed status, so **`./scripts/run_all.sh` fails on a clean clone**. Commit this first.

```bash
git status
```
```bash
git add scripts/calibrate_fusion.py tests/test_imports.py data/reports/evaluation_report.json docs/IMPLEMENTATION_STATUS.md docs/CODEBASE_AUDIT.md docs/GIT_WORKFLOW.md docs/TEAM_HANDOFF.md
```
```bash
git commit -m "Fix calibration script after status rename; test script imports; add status doc" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
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
| 1 to 13: contracts, data, Agents 1 to 3, campaigns, tools, policy, replay, API | `646744a`, with repairs in `upd2` and `up3` |
| Level 2 Agents 4 and 5 (not in the suggested list) | `upd2` and `up3` |
| 14 to 18: frontend | `646744a`, with additions in `upd2` and `up3` |
| 19 and 20: tests and verification | `upd2`, `up3` and step 2 |

The history cannot honestly be re-split into these milestones. Leave it as it is, and use clearer messages from here on: `upd2` and `up3` don't tell a reader or a judge what changed.
