# ADR-001: One shared scanning core, structured findings, narrow scopes

Status: Accepted. Deciders: repo owner.

## Context
Detection logic existed three times (Apps Script, extension, CLI) and had drifted: the extension popup was a mock, the CLI scanned only the first text/plain part and hard-coded `senderVerified: true`. The add-on called APIs its scopes did not cover, scored by matching warning strings, and used APIs Apps Script does not have (`URL`, `Utilities.unzip` with a password).

## Decision
1. One pure-JS file, `core/scanner-core.js`, with no platform APIs. Adapters do I/O and pass results in as `enrichment`; the core returns `{score, level, findings[], skipped[]}`. `npm run sync-core` copies it into each component and CI fails if a copy is stale.
2. Findings are structured `{id, severity, title, detail, evidence}`. Score is 100 minus distinct-id weights, level comes from worst severity and score. No string matching on user-facing text.
3. All three components read mail through the Gmail REST API (`format=full`) so they see identical data. The core normalizes it.
4. Skipped checks are returned and displayed. A failure never produces a clean verdict.
5. Scopes: `gmail.addons.execute`, `gmail.addons.current.message.readonly`, `gmail.modify`, `script.external_request`. Not `gmail.readonly` (redundant), not `mail.google.com` (would allow permanent delete), not `gmail.send` (reports are drafts the user sends).

## Options considered
| Option | Result |
| :-- | :-- |
| Keep three engines | Drift continues; rejected |
| Shared core, copied by script (chosen) | No build step Apps Script cannot run; needs the sync check |
| Publish core as npm package | Apps Script cannot import it; rejected |
| GmailApp for reading | Needs the full-access scope; rejected |
| Add-on scopes only (no `gmail.modify`) | Cannot label or move to Spam; rejected for this use |

## Consequences
- Easier: one place to add a detector, tests run in plain node, behavior is the same everywhere.
- Harder: the core must stay ES5-style and free of platform APIs; generated files must not be edited by hand.
- Unverified until tested on a real account: whether `current.message.readonly` is needed once `gmail.modify` is granted (it is kept, harmless), and Gmail DOM ids used by the extension's content script.
- Publishing publicly would trigger restricted-scope verification; the project stays unpublished.
