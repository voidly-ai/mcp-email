# Voidmail MCP Registry release order

This source branch prepares a **candidate** `@voidly/mcp-email` 1.2.1 release and a local stdio Registry record. A `server.json` file in GitHub does not mean that version is on npm or listed in the MCP Registry. The package README, `llms.txt`, and `context7.json` still point to the confirmed published 1.2.0 until a newer package is read back.

1. Merge the reviewed 1.2.0 source-mirror PR first. Before merging this release-prep PR, confirm that 1.2.1 is still unused on public npm; if it has been taken, choose a new version and update `package.json`, lockfile, MCP `serverInfo.version`, test, and `server.json` together.
2. Before merging the manual publisher workflow, create the GitHub environment `mcp-registry-publish` in `voidly-ai/mcp-email`, allow only `main`, and require an owner reviewer. The workflow's `environment:` field alone does not protect first use. Review the environment settings in GitHub after saving them.
3. Merge this source PR only after its exact-head tests and owner review. The owner then publishes the new npm package through the approved release path. Read back the **published** metadata and tarball: `name`, `version`, and `mcpName` must match `server.json` (`io.github.voidly-ai/mcp-email`). Source files alone cannot pass the Registry's npm ownership check.
4. After npm 1.2.1 is verified, update the README, `llms.txt`, and `context7.json` install/version references from 1.2.0 to 1.2.1. Verify their served or merged contents. Keep the initial `server.json` **local stdio only**; do not add `/mcp/mail` while it is merely proposed.
5. The owner reviews the merged manifest on `main`, manually runs **Publish Voidmail MCP Registry record** with `hosted_mcp_served` left false, approves the protected environment, waits for terminal workflow success, and reads back the exact Registry name/version/npm pin. Validation, login, or a started workflow alone is not publication.
6. A future remote version needs a new immutable Registry version and direct served MCP `initialize`/`tools/list` plus safety readback at `https://api.voidly.ai/mcp/mail`. Only then may the owner add the canonical Streamable HTTP remote, select the hosted checkbox, and submit another record.

No npm publish, Registry submission, environment change, mail send, or hosted deployment is performed by this repository file.
