# Deploy checklist: add-on, extension, CLI

Run once on a test Gmail account before trusting the tool. Tests in CI prove logic; only these steps prove it works against live Gmail.

## Pre-deploy
- [ ] CI green (`npm test`), `npm run check-core` clean
- [ ] PR #36 (code-scanning fixes) is already merged
- [ ] Dependabot #40/#41: `cd cli-extension && npm install @modelcontextprotocol/sdk@latest && npm update proxy-addr`, commit the lockfile
- [ ] Rollback: `git revert` the merge; add-on rollback = previous Apps Script version (Deploy > Manage deployments)

## Add-on
- [ ] `clasp push` shows only .gs files and appsscript.json
- [ ] Install test deployment, authorize all four scopes (expect "unverified app")
- [ ] Open a normal email: card shows green and header "Standard scan"
- [ ] Send yourself a test email from a second account with a fake `paypa1` brand link: card is not green and lists findings with evidence
- [ ] Open an email with no network (revoke Safe Browsing key): card lists it under "Not checked"
- [ ] Deep scan button changes the header to "Deep scan" (not served from cache)
- [ ] Neutralize moves the thread to Spam; undo from Spam
- [ ] Report creates a draft to reportphishing@apwg.org with reported.eml attached; nothing is sent
- [ ] Trust/Block and Settings persist after reopening
- [ ] Check Executions log for errors; confirm daily URL Fetch usage is low
- [ ] If the card never appears with `current.message.readonly` removed, re-add it (open question in ADR-001)

## Chrome extension
- [ ] Chrome Extension OAuth client created, `key` set, client id in manifest
- [ ] Popup scans the open message; if not detected, recent list works
- [ ] Failed scan (disconnect network) shows "NOT checked", not a score
- [ ] Move to Spam works; no permanent delete anywhere

## CLI / MCP
- [ ] `node index.js scan` works with only `GMAIL_*` set
- [ ] `quarantine <id> --yes` fails without `SCANNER_ALLOW_WRITE=1`
- [ ] MCP registered in Gemini CLI; `quarantine_thread` dry run first

## Rollback triggers
- Any scan returns a clean card for a message that failed to load
- Neutralize or report acts without a user click
- Unexpected scope prompt beyond the four listed
