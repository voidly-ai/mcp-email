# Voidmail MCP Registry release order

Current release: npm `@voidly/mcp-email` 2.1.0 (latest). The MCP Registry lists 2.1.0 as the latest `io.github.voidly-ai/mcp-email` record, published 2026-10-16T04:30:56Z, local stdio only, with its npm package pinned to 2.1.0. 2.0.2, 2.0.1 and 1.2.1 stay listed as older versions. This repository's `dist/`, `README.md`, `CHANGELOG.md` and `package.json` are the exact bytes of the published 2.1.0 tarball, and `npm run build` from `src/` reproduces `dist/` byte for byte.

A `server.json` file in GitHub does not mean that version is on npm or listed in the MCP Registry. Read both back.

For the next version:

1. Confirm the new version is unused on public npm. Update `package.json`, the lockfile, MCP `serverInfo.version` (`VERSION` in `src/server.ts`), the tests that pin it, `server.json` and the version checks in `.github/workflows/publish-mcp-registry.yml` together.
2. The manual publisher workflow must run in the GitHub environment `mcp-registry-publish`, limited to `main` with an owner reviewer. The workflow's `environment:` field alone does not protect first use. Review the environment settings in GitHub after changing them.
3. Merge the source PR only after its exact-head tests and owner review. The owner then publishes the new npm package through the approved release path. Read back the **published** metadata and tarball: `name`, `version` and `mcpName` must match `server.json` (`io.github.voidly-ai/mcp-email`). Source files alone cannot pass the Registry's npm ownership check.
4. After the npm version is verified, commit the tarball's `dist/`, `README.md` and `package.json` byte for byte (`dist/` is in `.gitignore`, so add it with `git add -f`). CI rebuilds `dist/` from `src/` and fails if it differs. Then update the pins in `llms.txt`, `context7.json` and `.mcp.json` and verify their merged contents. Keep `server.json` **local stdio only**; do not add `/mcp/mail` while it is merely proposed.
5. The owner reviews the merged manifest on `main`, manually runs **Publish Voidmail MCP Registry record** with `hosted_mcp_served` left false, approves the protected environment, waits for terminal workflow success, and reads back the exact Registry name, version and npm pin. Validation, login, or a started workflow alone is not publication.
6. A future remote version needs a new immutable Registry version and direct served MCP `initialize`/`tools/list` plus safety readback at `https://api.voidly.ai/mcp/mail`. Only then may the owner add the canonical Streamable HTTP remote, select the hosted checkbox, and submit another record.

No npm publish, Registry submission, environment change, mail send, or hosted deployment is performed by this repository file.
