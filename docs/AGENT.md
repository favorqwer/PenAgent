# PenAgent Agent Engine — Layered Agent Pipeline

`agent` is a second orchestration engine built on LangGraph 1.x. It keeps the
old `penagent` role chain (and its benchmark) untouched, and adds:

* LLM-written task plans (DAG) per phase, revised after failures;
* a real ReAct loop per task (command -> observation -> next command);
* a three-layer success verdict instead of "ask the model yes/no";
* layered budgets (task retry / phase replan / phase backtrack);
* command-level human approval with editable commands;
* checkpointed resume, time travel and cross-session target memory.

```
python cli.py agent -t 100.84.151.2
```

---

## 1. Three nested graphs

```
┌──────────────────── Engagement graph ────────────────────┐
│                                                          │
│  START → scope → collector → scanner → exploiter → reporter → END
│                      ▲          │           │             │
│                      │          └───────────┘             │
│                      └──────── backtrack (≤ max_backtracks)│
└──────────────────────────────────────────────────────────┘
                each box = the same phase subgraph
```

```
┌──────────────── Phase subgraph (collector / scanner / exploiter) ──────────────┐
│                                                                                │
│  START → planner → select_task ──(task)──► task subgraph ──► select_task       │
│             ▲            │                                         │            │
│             │            └──(none)──► handover → END               │            │
│             │                                                      │            │
│             └────────────── replan ◄────── failure / exhausted ────┘            │
└────────────────────────────────────────────────────────────────────────────────┘
```

```
┌──────────────── Task subgraph (one ReAct loop) ────────────────┐
│                                                                │
│  START → gen ──(tool calls)──► gate ──► run ──► gen ...        │
│           │                      │        │                    │
│           │                      └─(deny)─┘                    │
│           └─(finish/budget)──────────────────► evaluate → END  │
└────────────────────────────────────────────────────────────────┘
```

Why three levels: every failure class has one owner.

| Failure | Owner | Budget |
|---|---|---|
| SSH drop, gateway 429 | node retry / next LLM turn | per node |
| bad command, wrong flags | task ReAct loop | `max_steps_per_task` |
| task objective not reached | task retry, then replan | `max_task_attempts` |
| phase strategy wrong | replan | `max_replans` |
| phase cannot produce results | backtrack to scanning | `max_backtracks` |
| budget/time exhausted | reporter | `deadline_minutes`, `max_commands` |

---

## 2. State: three ledgers

| Ledger | Lives in | Reducer | Lifetime |
|---|---|---|---|
| Facts (ports, services+banner, vulns, creds, flags, tried vectors) | all three levels | append / deep-merge / dedupe | whole engagement + store across sessions |
| Plan (tasks, dependencies, status, result, evidence) | phase | **overwrite** (explicit new list) | one phase |
| Scratchpad (`messages`) | task | `add_messages` | one task attempt — dropped with the subgraph |

Subgraph schemas only expose the keys they need, so the scratchpad never reaches
the long-lived state and does not have to be cleared by hand.

Other keys: `phase`, `phase_summaries`, `action_history`, `phase_metrics`,
`plan_ids`, `deadline_ts`, `max_commands`, `commands_used`, `backtrack_count`,
`hitl_enabled`, `target_memory`.

Additive keys that cross a subgraph boundary use **deduplicating reducers**
(`merge_events` keyed by event id, `merge_unique` for strings): a nested subgraph
returns its whole list, so without dedupe the parent would merge it twice.

---

## 3. What one task does

```
select_task
  │  builds the kickoff: task + facts + prior-session memory (+ retry note)
  ▼
gen       LLM sees the whole transcript, emits tool calls (1 command per call)
  ▼
gate      policy classifies the command: read / probe / intrusive / destructive / unknown
          only intrusive+unknown require approval (unless --hitl-scope task)
  ▼
run       executes, appends one ToolMessage per call, extracts facts, logs actions
  ▼
gen ...   the model adapts based on the observation
  ▼
evaluate  three-layer verdict + result compression + plan update + DB projection
```

`gen` and `run` are separate nodes on purpose: the generated command is
checkpointed **before** execution. After a crash you know whether a command may
have run, which makes resume idempotent.

---

## 4. Verdict rules (the quality gate)

1. **Model self-report** — `finish_task(success=..., evidence=...)`.
2. **Objective evidence** — deterministic checks on the raw output:
   * any `uid=N(` or flag/meterpreter/root shell -> command execution proven;
   * `uid=0` / `flag{}` -> compromise proven;
   * error markers (`command not found`, `permission denied`, `[Exit Status:` ...) -> failure;
   * port table / CVE / directory hit / valid empty scan -> positive signal;
3. **Independent evaluator** — a separate LLM call that only sees a compact transcript.

Arbitration: hard positive wins, hard negative wins, otherwise require *both* the
model claim and the evaluator to agree (conservative). An exploit claim without
`uid=`/flag evidence is always recorded as a failure, even if the model insists.

---

## 5. Persistence

| Layer | Path | Purpose |
|---|---|---|
| Checkpointer | `data/graph_checkpoints.db` | execution truth; resume, time travel, HITL |
| LangSmith | `basic_config.yaml -> langsmith` | opt-in tracing; run names are `penagent/<phase>/<target>` |
| Projection | `data/penagent.db` (`plans`/`tasks`/`sessions`) | reports, benchmark, WebUI |
| Store | `data/graph_store.db` | cross-session knowledge keyed by target IP |
| Reports | `data/reports/<thread>.md` | final markdown report |

Projection uses delete+insert per plan, so `(plan_id, sequence)` never duplicates
(unlike the legacy `add_task_to_plan`).

Resume:

```
python cli.py agent -t 100.84.151.2 --thread-id my-run --resume
```

If the checkpoint is sitting on an approval interrupt, the CLI asks again before
continuing.

---

## 6. Commands

```bash
# full autonomous run
python cli.py agent -t 100.84.151.2

# no API calls, no SSH: scripted model + scripted shell
python cli.py agent -t 100.84.151.2 --dry-run

# command-level approval (intrusive/unknown commands only)
python cli.py agent -t 100.84.151.2 --hitl

# approve once per task instead of per command
python cli.py agent -t 100.84.151.2 --hitl --hitl-scope task

# budgets
python cli.py agent -t 100.84.151.2 --max-commands 120 --deadline 30

# global per-command timeout cap (the model may ask for less, never more)
python cli.py agent -t 100.84.151.2 --command-timeout 90

# resume / inspect
python cli.py agent -t 100.84.151.2 --thread-id my-run
python cli.py agent -t 100.84.151.2 --thread-id my-run --resume
```

Approval prompt choices: `y` approve, `n` deny with a reason, `e` edit the
command before approving, `a` approve the rest of the task.

If the model answers with a command in prose instead of a tool call, the task
loop extracts the first obvious command (`nmap`, `curl`, `gobuster`, ...) and
executes it through the normal approval gate. Two consecutive text-only turns
abort the task instead of looping forever.

---

## 7. Configuration

All defaults live in `agent/settings.py`; overrides go in
`config/yaml/agent_config.yaml` (budgets, per-node models, HITL policy, context
budgets, storage paths). Per-node model routing lets you use a strong model for
planning and a cheap one for commands/evaluation.

---

## 8. Extending

* **New phase**: add a `PhaseConfig` row in `agent/phases.py`, add the node
  + edge in `agent/graphs.py`. The phase subgraph is reused as-is.
* **New tool**: add a `@tool` in `agent/tools.py`, register it in `ALL_TOOLS`,
  add it to the phase `allowed_tools` tuple, and handle it in `run_node`.
* **Different risk policy**: edit `agent/policy.py`; unclassified commands
  are denied by default.
* **Different verdict rules**: `agent/findings.py::evidence_verdict`.

---

## 9. Tests

```bash
python -m unittest tests.test_agent -v
```

Covers reducers, plan merge/topology/blocking, risk policy, evidence extraction,
text-command fallback, a full scripted engagement (compromise + report + no
duplicated summaries), command-level HITL interrupt/resume, the
exploitation->scanning backtrack, and a real Kali SSH smoke test (skipped
automatically when the attack machine is unreachable).

---

## 10. Known limitations

* **One SSH channel**: tasks run sequentially by design. Do not fan out shell
  commands without adding a connection pool (`Send` is intentionally unused).
* **Risk policy is heuristic**: name-based allowlists plus destructive patterns.
  Unknown binaries always require approval, but aliases can slip through.
* **Structured output depends on the gateway**: three-step fallback
  (`function_calling` -> `json_mode` -> prompt+JSON) keeps it working on
  OpenAI-compatible gateways, at some cost in determinism.
* **Plan drift**: replanning matches old tasks by normalised instruction; a model
  that renames a successful task can duplicate work. Successful task text is fed
  back explicitly to mitigate this.
* **Evaluator cost**: one extra LLM call per task attempt.
