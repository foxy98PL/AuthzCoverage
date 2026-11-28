# Agent flow

Binding rules: `.claude/delegation-rules.md`. This page is a readable summary.

## Before the session

```mermaid
flowchart LR
    U([You: /planner]) --> P["planner<br/>Opus"] --> S[docs/sessions/sessionN.md]
```

## During the session (per ticket)

The orchestrator (Sonnet) repeats this loop for each ticket.

```mermaid
flowchart TD
    I["1. implementer (Sonnet)<br/>writes the code"] --> C["2. orchestrator<br/>runs make check"]
    C --> T{"3. docs-only change?"}
    T -- yes --> K
    T -- no --> R["reviewer (Sonnet, background)<br/>writes notes/KEY-review.md"]
    R --> F{findings?}
    F -- no --> K
    F -- yes --> X["fixer (Sonnet)<br/>one pass, no second round"]
    X --> K["4. orchestrator commits<br/>Conventional Commit + Jira key"]
    K --> N([next ticket])
```

## Optional agents in the flow

Dashed boxes are optional: they run only when their condition is met.

```mermaid
flowchart TD
    I["1. implementer"] --> C["2. make check"]
    C --> T{"3. docs-only?"}
    T -- yes --> K
    T -- no --> R["reviewer"]
    R --> F{findings?}
    F -- no --> K
    F -- yes --> X["fixer"]
    X --> K["4. orchestrator commits"]
    K --> N([next ticket])

    A[/"advisor (Opus)<br/>security or architecture question"/]:::opt -. "before design or when the reviewer cannot settle a security finding" .-> I
    A -.-> R
    V[/"validator (Sonnet)<br/>fuzz, eval, determinism, scans"/]:::opt -. "long or noisy checks" .-> C
    K -.-> J[/"jira (Haiku)<br/>batched updates"/]:::opt
    N -. "session end or ~150k tokens" .-> J

    classDef opt stroke-dasharray: 5 5
```

| Optional agent | Model | Spawned when |
|---|---|---|
| validator | Sonnet | Long or noisy checks: fuzz, eval, determinism diffs, secret/HAR scans. Plain `make check` is run by the orchestrator. |
| advisor | Opus | Security or architecture question, written first to `notes/KEY-opus.md`. Also when the reviewer cannot settle a security finding. |
| jira | Haiku | Batched Jira updates at the end of a session or at a restart, not per ticket. |

## Restart

At about 150k tokens (hook warns at 120k) the orchestrator writes a progress shard in `docs/progress/`,
sends the batched Jira updates and stops. You continue with `/resume`.

## Rules of thumb

- Every code change gets a reviewer pass, however small.
- Dependent steps: run in sequence. Parallel only for independent tickets in disjoint directories.
- Prompts to agents: pointers only, at most ~1.5k tokens. Details go to `notes/`.
- Agents never commit or push. Only the orchestrator does.
