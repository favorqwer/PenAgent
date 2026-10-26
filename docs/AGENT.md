# PenAgent Agent Engine — Layered Agent Pipeline

`agent` is a second orchestration engine built on LangGraph 1.x. The legacy
`penagent` role chain (`roles/`, `actions/`) and its benchmark are untouched.

What the engine provides:

* LLM-written task plans (DAG) per phase, revised after failures;
* a real ReAct loop per task (command → observation → next command);
* one LLM judge per task, given the tool output and nothing the model said about it;
* failures handed to the planner verbatim (no classification step);
* layered budgets (task retry / phase replan / phase backtrack / stall guard);
* command-level human approval with editable commands;
* checkpointed resume, checkpoint history, and forking from a past checkpoint;
* cross-session target memory;
* per-node LLM usage accounting (calls and tokens).

```
python cli.py agent -t 100.84.151.2
```

---

## 1. Three nested levels

Engagement level (top):

```
START → scope → collector → scanner → exploiter → reporter → END
exploiter → backtrack → scanner   (at most max_backtracks times)
```

Phase level (the same subgraph is mounted three times):

```
START → planner → select_task → task subgraph → select_task ...
                        └── (nothing runnable) ──→ handover → END
task failure → replan (budget left) → select_task
                 └─ (replans spent) ──→ handover → END
```

Task level (one ReAct loop):

```
START → gen → gate → run → gen ... → evaluate → END
          └─ finish_task / step budget / stall ─────┘
```

Each level owns exactly one class of failure, so a retry never re-does work that
a higher level is responsible for:

| Failure | Owner | Budget |
|---|---|---|
| gateway 429/5xx, timeouts, dropped links | node retry policy | `llm_retries` |
| bad command, wrong flags, tool missing | task ReAct loop | `max_steps_per_task` |
| task objective not reached | task retry, then replan | `max_task_attempts` |
| phase strategy wrong | replan (the planner sees the failure verbatim) | `max_replans` |
| phase cannot produce results | backtrack to scanning | `max_backtracks` |
| loop is idling (same output, no new facts) | stall guard | `max_stall_rounds` |
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

Task-level additions: `last_fingerprint` and `stall_count` (convergence guard).

Other keys: `phase`, `phase_summaries`, `action_history`, `phase_metrics`,
`plan_ids`, `deadline_ts`, `max_commands`, `commands_used`, `backtrack_count`,
`hitl_enabled`, `target_memory`.

Additive keys that cross a subgraph boundary use **deduplicating reducers**
(`merge_events` for event lists, `merge_unique` for strings): a nested subgraph
returns its whole list, so without dedupe the parent would merge it twice.
Reducers must satisfy "merging the same delta twice changes nothing" — this is
asserted by randomised property tests, not assumed.

---

## 3. What one task does

`select_task` assembles the kickoff: task instruction, known facts, prior-session
memory, and (on a retry) the previous verdict.

`gen` calls the model with the phase toolset. Before the call the transcript is
trimmed to the context budget (see §6). The model must answer with a tool call;
a prose answer gets one reminder, and two consecutive text-only turns end the
task. Nothing is salvaged from the prose: a command the model did not emit is a
command it did not mean.

`gate` classifies every pending command as read / probe / intrusive / destructive
/ unknown. Only intrusive and unknown require approval, and only in the phases
listed in `hitl.require_approval_phases`.

`run` executes the calls and records structured outcomes: success, exit code,
timeout flag, duration, and the raw payload. Two guards live here:

* **unknown tool** — a hallucinated tool name is not executed, not charged to the
  budget, and answered with the list of tools available in this phase plus a
  "did you mean" hint;
* **stall guard** — two consecutive *repeats* of the same observation (three
  identical observations in a row) with no new facts end the task early. One
  repeat is not enough: two different paths returning 404 look identical.

Repeated commands are executed again. There is no result cache and no read-only
classification: a re-run may legitimately see a changed target, and the prompt
already tells the model which commands it has run.

`evaluate` produces the verdict (§4), compresses the result, updates the plan and
projects it into the reporting tables.

`gen` and `run` are separate nodes on purpose: the generated command is
checkpointed **before** execution. After a crash you know whether a command may
have run.

---

## 4. Verdict

One judge: the evaluator model. Every finished task — `finish_task`, step budget
exhausted, or stall — costs exactly one evaluator call.

* It sees `observations_digest`: tool output plus the commands that produced it.
  Never the assistant's own text or `finish_task` arguments, so a hallucinated
  "uid=0" cannot pass as proof.
* `finish_task(success=...)` only ends the task. It does not decide the verdict,
  and no agreement between it and the evaluator is required.
* The prompt states what counts: a scan or probe that completed satisfies an
  objective that asked for that scan even when the result is negative (no open
  ports, no directories, empty UDP reply); only a command that failed outright
  (nonzero exit, timeout) counts as failure.

Deterministic code is limited to facts, never judgements:

| Use | Where |
|---|---|
| extract ports, services, CVEs, flags, credentials from output | `agent/findings.py → extract_findings` |
| decide whether the target is compromised | `agent/findings.py → has_compromise_evidence` (`uid=0`, flag, root prompt, meterpreter) |

`is_compromised` is therefore set only by evidence found in output: the evaluator
cannot mark a target compromised, and no report can claim root without a
`uid=0`/flag artifact.

Cost is one call per task, visible as the `evaluator` row of the run-cost table
(~2.5k prompt tokens in the lab runs). The trade is deliberate: a rule that
misses costs a wrong verdict plus wasted commands, a call costs tokens.

---

## 5. Failure handling

There is no classification step. When a task exhausts its retries the graph goes
straight to `replan`, and the planner receives the failure in its own words:

```
THE LAST ATTEMPT FAILED (change the tool, parameters or angle; do not repeat it)
Task: ...
Last command: ...
Why it did not work: <the evaluator's reason>
Last observed output: <up to 600 chars of the decisive output>
```

The same one-line summary is appended to `tried_vectors`, which is rendered into
every later planning prompt as "already attempted and failed" and into the report.

There are no `failure_type` / `failure_strategy` fields. A word list can only
classify what someone already thought of (a WAF page, a service that answers with
noise, a tool that writes to stderr and still succeeds), and a wrong class sends
the replan in a wrong direction. The model reads the actual output instead.

---

## 6. Context and cost

Context is bounded three ways, from coarse to fine:

| Budget | Default | What happens |
|---|---|---|
| `max_tool_output` | 6000 chars | one observation is truncated head+tail before entering the transcript |
| `max_task_context_chars` | 24000 chars | older turns are dropped from the *invocation* (state keeps them) |
| `max_task_messages` | 18 | hard cap on message count per invocation |

Trimming keeps the system prompt and the task kickoff unconditionally, drops
whole tool-call/observation pairs (never half a pair), and replaces the dropped
part with one note listing the commands already executed, so the model does not
re-run them.

Usage accounting labels every model call with the node that made it and records
calls, prompt tokens and completion tokens per node (planner, command, evaluator,
summarizer, reporter). The totals appear in the report under `## Run cost` and in
the terminal as a table, together with the number of task verdicts (one per
finished task).

Per-node model routing (`models.planner`, `models.command`, ...) is what makes
this accounting actionable: planning and evaluation can use a strong model while
command generation uses a cheap one.

---

## 7. Persistence, resume, history, forking

| Layer | Path | Purpose |
|---|---|---|
| Checkpointer | `data/graph_checkpoints.db` | execution truth; resume, history, fork, HITL |
| Store | `data/graph_store.db` | cross-session knowledge keyed by target IP |
| Reports | `data/reports/<thread>.md` | final markdown report |
| LangSmith | `basic_config.yaml → langsmith` | opt-in tracing; run names are `penagent/<phase>/<target>` |

Resume continues from the newest checkpoint. If that checkpoint sits on an
approval interrupt, the CLI asks again before continuing.

History prints the checkpoint timeline of a thread: time, checkpoint, step,
phase, cumulative command count, next node, and flags (compromised / awaiting
approval). On narrow terminals the checkpoint and step columns are dropped
instead of squeezing everything.

Forking re-runs from a past checkpoint, keeping everything before it: a run whose
exploitation phase went wrong can be restarted from the end of scanning without
re-scanning the target. The new branch is appended to the same thread, so the
original history stays available.

Checkpoint ids inside one thread share their leading characters, so the history
view prints and accepts the **trailing** six characters.

---

## 8. Commands

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

# resume the newest checkpoint of a thread
python cli.py agent -t 100.84.151.2 --thread-id my-run --resume

# inspect the timeline (no target needed)
python cli.py agent --history --thread-id my-run

# fork from a past checkpoint (the trailing id from --history is enough)
python cli.py agent -t 100.84.151.2 --thread-id my-run --from-checkpoint a52277
```

Approval choices: `y` approve, `n` deny with a reason, `e` edit the command,
`a` approve the rest of the task. Denying twice ends the task instead of looping.

If a run aborts (retries exhausted), the CLI prints the reason plus the two
commands needed to inspect and resume it, instead of a traceback.

---

## 9. Configuration

Defaults live in `agent/settings.py`; overrides go in
`config/yaml/agent_config.yaml`.

`budgets`

| Key | Default | Meaning |
|---|---|---|
| `deadline_minutes` | 60 | wall-clock budget for the engagement |
| `max_commands` | 250 | global command budget |
| `max_backtracks` | 1 | exploiter → scanner fallbacks |
| `max_task_attempts` | 2 | retries of one task |
| `max_replans` | 2 | plan rewrites per phase |
| `max_steps_per_task` | 8 | model turns inside one task |
| `llm_retries` | 3 | node-level retries for transient LLM/gateway errors |
| `max_stall_rounds` | 2 | consecutive repeats of the same observation (no new facts) before the task ends |
| `max_tasks_per_phase` | 3 / 4 / 5 | collector / scanner / exploiter |
| `phase_share` | 0.3 / 0.3 / 0.4 | share of `max_commands` a phase may spend |

`context`

| Key | Default | Meaning |
|---|---|---|
| `max_tool_output` | 6000 | per-observation truncation |
| `max_task_messages` | 18 | hard cap on messages per invocation |
| `max_task_context_chars` | 24000 | soft cap; older turns are summarised away first |
| `max_result_chars` | 800 | task result fed back to the planner |
| `max_evidence_chars` | 4000 | evidence stored per task |
| `max_observation_chars` | 1800 | digest of one observation kept in the transcript (head + signal lines + tail) |
| `max_planner_facts` | 4000 | facts rendered into the planning prompt |

`hitl`: `enabled`, `require_approval_phases` (default `[exploiter]`),
`auto_approve_risk` (default `[read, probe]`), `max_denials` (2).

`models` / `temperatures`: per-node overrides (`planner`, `command`, `evaluator`,
`summarizer`, `reporter`). An empty model name falls back to
`model_config.yaml → llm_model_name`. `models.reasoning_effort` (default `none`)
and `models.reasoning_effort_by_node` suppress the gateway's thinking tokens;
`models.respect_env_proxy` (default false) opts into `HTTP(S)_PROXY`.

`storage`: `checkpoint_path`, `store_path`, `report_dir`.

---

## 10. Extending

* **New phase**: add a `PhaseConfig` row in `agent/phases.py` and the node plus
  edge in `agent/graph.py`. The phase subgraph is reused as-is.
* **New tool**: add a `@tool` in `agent/tools.py`, register it in `ALL_TOOLS`,
  handle it in `run_tool` (structured outcome), and add it to the phase
  `allowed_tools` tuple.
* **New failure class**: there is none to add. The planner reads the failed
task, its last command and the evaluator's reason directly.
* **Different risk policy**: edit `agent/policy.py`; unclassified commands are
  denied by default.
* **Different verdict rules**: the judge is the LLM — edit `EVALUATOR_SYSTEM` /
  `EVALUATOR_USER` in `agent/prompts.py`. Fact extraction lives in
  `agent/findings.py`.
* **New context policy**: `agent/context.py → trim_for_context` and
  `observation_digest`.

---

## 11. Tests

```bash
python -m unittest discover -s tests -t .
```

96 tests, no API key and no SSH required (one real-SSH smoke test skips itself
when the attack box is unreachable).

| Module | Covers |
|---|---|
| `test_agent.py` | reducers, plan merge/topology/blocking, risk policy, fact extraction, a full scripted engagement, HITL interrupt/resume, backtrack |
| `test_state_properties.py` | randomised reducer properties: stability, identity, no data loss, banners never erased |
| `test_tool_layer.py` | exit-code classification, context trimming invariants, unknown tools, stall guard |
| `test_plan_diagnosis.py` | plan merging: identical instructions keep their result, different ports stay separate |
| `test_retry_history.py` | retry classification and mechanics, checkpoint history, fork-from-checkpoint |
| `test_usage.py` | token accounting (gateway-style and message-style payloads), verdict counter |
| `test_memory_store.py` | cross-session memory round trip against the real store |

---

## 12. Invariants — do not break these

These are the traps that cost real debugging time; each one has a test or a
comment at the place it matters.

1. **An interrupting node is replayed on resume.** `gate` does pure computation
   before `interrupt()`; never add a side effect (a DB write, a log line that
   matters) before the interrupt.
2. **Counters are absolute and overwritten at subgraph boundaries.** `run`
   returns the new total for `commands_used`; there is deliberately no additive
   reducer, because the parent would then add the child's total a second time.
   Switching to fan-out requires redesigning this.
3. **Reducers must be stable.** Merging the same delta twice must be a no-op —
   subgraph boundaries do exactly that.
4. **Retry policies never go on `run`.** Replaying a node with real side effects
   runs the commands twice.
5. **Tool calls and their observations are trimmed as a pair.** Half a pair is
   rejected by the provider.
6. **The store connection must be autocommit; the saver must not be.**
   `SqliteStore` issues explicit BEGIN/COMMIT, `SqliteSaver` relies on implicit
   transactions. Sharing one connection makes every memory write fail silently.
7. **Checkpoint ids share a prefix per thread.** Match suffixes, not prefixes.
8. **The evaluator is the only judge.** `finish_task(success=...)` ends a task,
   it does not decide the verdict; and `is_compromised` must keep coming from
   output evidence only, never from a model statement.

---

## 13. Known limitations

* **One SSH channel.** Tasks run sequentially by design; there is no connection
  pool, so no fan-out. `Send` is intentionally unused.
* **Node-level timeouts are async-only** in LangGraph 1.2. Timeouts are enforced
  where they matter instead: per-command in the shell layer (including a PTY
  watchdog that sends Ctrl-C), and by the HTTP client for the model.
* **Risk policy is heuristic.** Name-based allowlists plus destructive patterns;
  aliases can slip through. Unclassified binaries always need approval.
* **Structured output depends on the gateway.** Three-step fallback
  (`function_calling` → `json_mode` → prompt+JSON) keeps it working, at some cost
  in determinism.
* **Plan drift is mitigated, not eliminated.** Reworded successful tasks are
  matched only by normalised instruction or id, so a paraphrase creates a
  duplicate task. The planner sees the completed list and normally avoids it.
* **Usage accounting is process-global.** Correct for one engagement per process;
  an API server needs it keyed by thread id.
* **New facts do not trigger a replan.** Tasks are only added by the planner at
  phase start or after a failure; discovering something the plan does not cover
  waits for a failure.
* **SQLite checkpointer is single-connection.** Fine for the CLI; concurrent
  threads need a different backend.
* **Every verdict costs a call.** One evaluator call per finished task, and there
  is no deterministic fallback: if the evaluator stays unavailable after the node
  retry budget, the run aborts instead of guessing.
