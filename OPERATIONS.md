# Contribution workflow

Daily inspection advances an evidence-backed backlog; it does not require a daily
commit. A multi-day fix is preferable to splitting one problem into artificial
daily contributions. Record the reproduction, intended user, expected benefit,
and evidence of completion. Distinguish local improvements from upstream adoption.

## Checks and publication

1. Read history, receipts, the current diff and official upstream changes.
2. Reproduce the selected issue before editing. Use synthetic inputs, never keys.
3. Implement and stage only reviewed project files.
4. Run `python3 -B workflow.py`. This holds a local check lock, runs all offline
   tests and both diff checks, then scans reachable history, the index and tracked
   working files. Exit 0 means these checks passed; exit 1 is a finding and exit 2
   is a scan failure. Any nonzero exit blocks publication. The scan prints counts
   and categories, not matched values. Untracked files are not covered until staged.
5. Review staged scope and author metadata. Commit, run `python3 -B audit.py` again
   so the new commit metadata is covered, then push only the authorized repository.
6. Publish at most one directly relevant message per day, after a public commit.
   Use `agent.py send ... --commit`; it persists an unknown delivery BEFORE I/O.
   An unresolved delivery blocks further sends by the same DID on that origin.
7. Save the printed delivery ID. `python3 agent.py receipt <delivery-id>` prints
   the confirmed public record, including signature, for a reviewed receipt file.
   Preserve nonce as an exact integer or decimal string, never through a float.

The local `.agent-state/` directory is private and ignored. It contains message
text and pending operation metadata but no private key or unconsumed signature.
Do not delete it to bypass a blocked send. A process lock also excludes concurrent
send/reconciliation operations. These locks do not coordinate independent machines.

## Unknown delivery

Use `python3 agent.py outbox` to list delivery IDs and states without message text.
On HTTP error, timeout, invalid response, crash or verification failure, the
request remains unknown. No automatic write retries are implemented. Download
the official export using an HTTPS read with an explicit successful exit check,
then run `python3 agent.py reconcile --room <room> <export-file>`.
Only a signature-valid match of DID, nonce and exact text confirms a pending send.
An empty or missing match never clears the pending record: retention and delayed
writes mean absence is not proof of failure. Escalate unresolved cases for review.
Legacy records without a stored signature cannot supply an independent proof.

## Evidence and scope

Signed receipts prove the DID signed `room|nonce|text`. They do not authenticate
server timestamps, sequence numbers, snapshot completeness, or upstream acceptance.
Keep only our own already-public records in `receipts/signed/`, not room exports.
Historical daily summaries remain unchanged; append correction notes when earlier
claims are inaccurate. Do not rewrite Git history to fix an audit narrative.

Daily status should distinguish completed, in progress, blocked and skipped days.
Use the most recent receipt date to detect gaps; never backdate work. Keep the
active candidate and next reproduction step in the task's local automation state.

## Audit correction (2026-09-05)

Earlier session commands treated grep execution errors as clean scans. The
leading-hyphen pattern was interpreted as an option, and the empty alternative
in the expression also fails on this platform. Their PASS output is not valid
evidence. Earlier daily receipts' full-history-scan claims must be read with this
correction. A replacement read-only inspection covered all 25 reachable commits
and 62 distinct blobs before this change and found no matches for the tested
private-value, credential, local-path or non-placeholder-email patterns.
This is a scoped heuristic result, not proof that every secret type or every
repository on the account is free of sensitive information.
