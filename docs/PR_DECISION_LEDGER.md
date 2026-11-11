# PR Decision Ledger — 2026-11-11

## Summary

6 open PRs reviewed. Recommendations below; merging requires repo owner approval.

## Decisions

### PR #264 — fix(lua-check): report unreadable probe instead of aborting
**Author:** ArjunD717
**Recommendation:** MERGE
**Rationale:** Clean 3-file fix. Moves file read inside try block so one bad probe doesn't abort the whole scan. Includes test. CI partial (1/3 jobs visible as passed). Low risk, high utility.

### PR #263 — fix(regen): remove calendar date from generated archives
**Author:** ArjunD717
**Recommendation:** MERGE
**Rationale:** Removes `date.today()` from archive banner that caused `--check` to report STALE daily even with no changes. 4 files, includes regression test. CI partial pass. Straightforward fix.

### PR #243 — docs: post-#240 corrections + serve.py /beaconish fix
**Author:** jsrkamal2002
**Recommendation:** CLOSE (superseded by #246)
**Rationale:** Reviewers (ArjunD717, ng643) identified it as dirty/conflicting. The `serve.py` fix already landed via #247, the inventory is re-pinned by #256. #246 is the broader superset. Consensus: keep #246, close #243.

### PR #245 — docs(index): flag p765/p768/p769 legs as config-silent (JIT OFF)
**Author:** jsrkamal2002
**Recommendation:** CLOSE (duplicate of #243, superseded by #246)
**Rationale:** Repeats #243 changes plus adds config-silent flags. ArjunD717 and ng643 explicitly recommend closing. #246 covers this.

### PR #246 — docs: fold cobrajet302gt corrections (LLInt-only, p807 RVA [I], 4KiB page frame)
**Author:** jsrkamal2002
**Recommendation:** BLOCKED — needs rebase
**Rationale:** Most comprehensive of the three jsrkamal PRs. Important corrections: LLInt-only JIT tier, p807 RVA downgrade to [I], 4KiB page-frame erratum. BUT: 3 conflicts (CLAUDE.md, EXPLOITATION_STATUS.md, serve.py), `render_progress.py --check` fails. Needs rebase onto current master. After our CLAUDE.md overhaul, the CLAUDE.md conflict is guaranteed since the file structure changed. Author or maintainer must rebase. **Note:** Our slim CLAUDE.md already removed the sections #246 tried to edit, so the corrections need to go into the reference docs instead.

### PR #250 — Research/tfujiwara v919 v929 campaign
**Author:** TFujiwara
**Recommendation:** BLOCKED — needs cleanup
**Rationale:** Large (191 files, +46K lines, 98 commits). WebKit research on 14.22/14.10. Three blockers identified by ArjunD717:
1. p690/p691 committed as UTF-16LE with BOM (should be UTF-8)
2. p704 double-booked; renamed p681 still carries old identifiers
3. Eleven zero-byte beacon logs as evidence
No CI results. No reviews submitted. Valuable research but needs encoding fixes, deduplication, and empty-file cleanup before merge.

## Action Items — COMPLETED 2026-11-11
- [x] Merge #264 and #263 — merged via gh CLI
- [x] Close #243 and #245 with explanation — closed with detailed rationale
- [x] Cherry-pick #246 corrections into integration branch, close with credit
- [x] Comment on #250 re: remaining blockers (p704 naming, 29 zero-byte logs)
- [x] Integration PR #265 created, CI 6/6 pass, merged into master
