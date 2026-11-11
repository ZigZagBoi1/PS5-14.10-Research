# Research Checkpoint

## Last Updated
2026-11-11T15:00:00Z

## Phase
Phase 0 — Repository Overhaul (Priority A) — COMMITTED
Phase 1 — PR Review (Priority C) — COMPLETE

## Completed
- [x] CLAUDE.md: 581→162 lines, 26.5K→1.6K tokens (94% reduction)
- [x] Extracted docs/DEAD_ENDS_REFERENCE.md (142 lines)
- [x] Extracted docs/ATTACK_PRIORITY_REFERENCE.md (150 lines)
- [x] Checkpoint system (this file)
- [x] PR audit: 6 open (#243 #245 #246 #250 #263 #264)
- [x] Committed: overhaul (52792434), phase17 probes (ccc91194), docs+tools (ebe1d825)

## Open PRs
| # | Author | Title |
|---|--------|-------|
| 264 | ArjunD717 | fix(lua-check): report unreadable probe |
| 263 | ArjunD717 | fix(regen): remove calendar date |
| 250 | TFujiwara | Research v919/v929 campaign |
| 246 | jsrkamal2002 | docs: cobrajet302gt corrections |
| 245 | jsrkamal2002 | docs(index): flag config-silent |
| 243 | jsrkamal2002 | docs: post-#240 corrections + serve.py |

## PR Review Complete
See docs/PR_DECISION_LEDGER.md. #264/#263 recommended for merge, #243/#245 for close, #246/#250 blocked.

## Next Action
1. Push commits + merge #264/#263 (needs owner approval or gh CLI)
2. Build search index (SQLite FTS5)
3. Evidence reconstruction (capability graph)
4. External research audit

## Git State
- Branch: master, HEAD: ebe1d825 (4 ahead of origin)
- Working tree clean
