# Changelog

## 2.1.0

- **Create an inbox in one command.** `voidly-mcp-email create [--name <name>] [--address <local part>]` makes one inbox, saves its agent key and owner key to 0600 files and prints only the address and file paths. No key, signature or API key is printed.
- **Creator identity without setup.** With no `VOIDMAIL_CREATOR_SIGNING_KEY_FILE`, `create` and `voidmail_create_account` use a dedicated creator identity in `<key dir>/creator/identity.json`, enrolling one first through Voidly Home join (`POST /v1/home/join`, the agent-sdk 4.0 protocol). Keys are made on this machine; only public keys, API-key hashes and signatures are sent. The join message is checked line by line before it is signed, and every key is saved (0600) before the commit is sent. A commit whose answer is lost is replayed on the next run; it never makes a second identity. The identity file has the agent-sdk `exportCredentials()` shape. `VOIDMAIL_CREATOR_AUTO_ENROLL=off` turns enrollment off.
- **agent-sdk identity exports.** `VOIDMAIL_CREATOR_SIGNING_KEY_FILE` also accepts an `@voidly/agent-sdk` `exportCredentials()` JSON file; its DID is read from the file (`VOIDMAIL_CREATOR_DID`, if set, must match). The 2.0 raw 64-byte format still works.
- **Verification mail.** New read-only tools `voidmail_wait_for_email` (waits up to 25 seconds; exact sender, subject text and `since` filters) and `voidmail_extract_code` (a likely one-time code and HTTPS verification link from one message's plain text). Matching runs on this machine, so both work on sealed inboxes; neither marks mail read, follows a link or returns HTML. The inbox API has no server-side sender, subject, time or cursor filter, so those filters run here.
- **README.** "Create an inbox in one command" comes first, then a "Get a DID" fallback and Node.js and Python signed-create examples. Wording: mail to a new inbox is readable by the server; not end-to-end encrypted.
- The server create contract is unchanged.

## 2.0.2

2.0.0 and 2.0.1 were built without three fixes that shipped in 1.2.1. 2.0.2 restores them from 1.2.1:

- **Requested address.** `voidmail_create_account` takes a local part (for example `myagent`) or its exact `myagent@voidmail.ai` address, and puts only the lowercase local part in the signed create request. 2.0.0 and 2.0.1 sent a full address as given, which the API refuses. A name the API would refuse (under 3 or over 30 characters, not starting with a letter, or containing `..`) is refused before any work proof or request.
- **List and search bounds.** `voidmail_list_inbox` states the API's real default of 50 messages (max 100). `voidmail_search_inbox` refuses an empty or blank query before any request and ignores surrounding spaces. Its result limit stays at 100, because 2.0 searches on this machine, not through the server search route.
- **Webhook text.** `voidmail_set_webhook` says up front that the agent key can set a webhook only on an open-policy inbox without an owner key. On an allowlist inbox, or any inbox with an owner key, the human owner uses `POST /v1/agent-mail/owner/webhook` with the owner key.
