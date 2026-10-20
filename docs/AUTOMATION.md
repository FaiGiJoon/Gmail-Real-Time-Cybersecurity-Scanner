# Claude Code automation recommendations

Codebase: Apps Script add-on, Chrome MV3 extension, Node MCP server, one shared core.

## Hook (highest value)
PostToolUse on Edit/Write of `core/scanner-core.js`: run `npm run sync-core`. Prevents the generated copies drifting.
`.claude/settings.json`:
```json
{ "hooks": { "PostToolUse": [ { "matcher": "Edit|Write", "hooks": [ { "type": "command", "command": "node scripts/sync-core.js" } ] } ] } }
```
Second hook: PreToolUse block edits to `ScannerCore.gs`, `browser-extension/scanner-core.js` and `cli-extension/scanner-core.cjs` (generated).

## Skill
`/add-detector`: a user-invoked skill that adds a finding id, weight and test in `core/`, runs `npm test`, and reminds you to update the README list.

## Subagent
`security-reviewer` (read-only tools) to review diffs that touch scopes, `quarantine`/`neutralize` paths or anything that renders email text into HTML, a card or an MCP result.

## MCP server
GitHub MCP for PR and Dependabot work. Optional: context7 for current Apps Script / Chrome extension docs.

Ask for more in any category if useful.
