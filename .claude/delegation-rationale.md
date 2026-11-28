# Why the delegation rules look the way they do (measurements)

Not loaded at startup. Grep here when a rule in `.claude/delegation-rules.md` needs justifying or revisiting.

- **Subagent floor (2026-11-27, 10 subagents, `notes/orchestrator-state.md` → "Context audit"):** any subagent
  starts at ~35k tokens (system prompt + skill listing ≈ 13k, CLAUDE.md, MCP/agent listings); a "reply OK"
  agent cost 34.6k. Everything above the floor came from the agent's own whole-file reads (70–98% of tool
  output), the code it wrote, full test/golden output, and SendMessage resumes. Prompts were 0.4–1.8k tokens,
  never the driver. → §2 prompt cap, §3 read hygiene, §4 hook, skip-review / inline-check rules.
- **Resumes keep the whole context:** KAN-92 went 144k → 161k → 177k over two resumes. → §6.
- **Orchestrator re-reads dominate:** 4 Opus orchestrator sessions re-read 132M tokens (peaks 336–492k) vs 62M
  for all 69 subagents together. The cost of any output is its size × the turns left. → Sonnet orchestrator,
  restart threshold, §7.
- **Opus vs Sonnet:** Opus costs 2× Sonnet per token (input, output, cache reads). → Opus only as a fresh
  agent for security/architecture questions.
- **Polling:** 12–15 poll turns per session ≈ 2.5M tokens each session. → never poll.
- **Jira echoes:** a transition or `getJiraIssue` echoes the full issue (~4–5k chars); one session made 22
  such calls. → one batch at the end, slim responses.
- **Restart threshold:** a reload costs ~45k. Restart at 150k → average context per turn ≈ 97k; at 100k ≈ 72k.
  Owner chose 150k (2026-11-28) for fewer interruptions.
