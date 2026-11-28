# Why the delegation rules look the way they do (measurements)

Not loaded at startup. Grep here when a rule in `.claude/delegation-rules.md` needs justifying or revisiting.

- **Subagent floor:** on 2026-11-27 any subagent started at ~35k (full system prompt + skill listing). With the
  lean `.claude/agents/` definitions, they start at ~6k (audit 2026-11-28); `general-purpose` still starts at ~32k.
  Above the floor, cost came from the agent's own whole-file reads (70–98% of tool output), the code it wrote,
  full test/golden output and SendMessage resumes. Prompts (0.1–0.8k) never drove it. → §1 lean agents only,
  `advisor` for Opus, §2 prompt cap, §3 read hygiene, §4 hook, skip-review / inline-check rules.
- **Unscoped audits:** 4 Haiku "done-readiness audits, no diff" took 150 turns, 6.7M cache reads and peaked at
  82–95k each, while scoped reviews took 4–9 turns and peaked at 9–36k (2026-11-28). → §2 audit scope.
- **Resumes keep the whole context:** KAN-92 went 144k → 161k → 177k over two resumes. → §6.
- **Orchestrator re-reads dominate:** 4 Opus orchestrator sessions re-read 132M tokens (peaks 336–492k) vs 62M
  for all 69 subagents together. The cost of any output is its size × the turns left. → Sonnet orchestrator,
  restart threshold, §7.
- **Opus vs Sonnet:** Opus costs 2× Sonnet per token (input, output, cache reads). Opus orchestrators: 28.6–54.6M
  cache reads per session; Sonnet orchestrators: 1.5–4.2M (2026-11-28). → Opus only via `advisor`.
- **Polling:** 12–15 poll turns per session ≈ 2.5M tokens each session. → never poll.
- **Jira echoes:** a transition, create or `getJiraIssue` echoes the full issue (~4–5k chars), and writes take no
  `responseFields`. One Sonnet session's 19 transitions + 22 creates returned 121k chars (~30k tokens) that stayed
  in context for every later turn (2026-11-28). → one batch at the end, run by the Haiku `jira` agent.
- **Startup floor:** the orchestrator's first turn was 32–41k (2026-11-28), mostly built-in tool, agent-type and
  skill descriptions it never uses; each turn re-reads it. Estimated 7–9k saved by the deny list and skill
  overrides → §8. Verify: first-turn usage of the next session (baseline 32k).
- **Restart threshold:** a reload costs ~45k. Restart at 150k → average context per turn ≈ 97k; at 100k ≈ 72k.
  Owner chose 150k (2026-11-28) for fewer interruptions.
