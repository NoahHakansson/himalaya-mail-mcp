# himalaya-mail-mcp design

A small Go MCP server that exposes typed mail tools and runs a pinned Himalaya v2.2.1 binary with fixed argv. It cannot send mail, delete mail permanently, or run arbitrary commands.

(V) means verified against the pinned binary, its source at the pinned rev, or the Dovecot test fixture. (U) means unverified. Proton Bridge behaviour marked (V) was read from the Bridge source, not observed on a running Bridge.

## 1. Shape and pins

- One binary, `himalaya-mail-mcp -config <abs path> <stdio|http|check>`.
  - `check` runs the startup checks from section 5, then a login and capability probe per account. It prints one line per account and exits non-zero on any failure. It is meant for setup and recovery.
- Chain: an MCP client over stdio, or over HTTP with a bearer token, then this wrapper, which starts one Himalaya process per step, which talks STARTTLS with a pinned certificate to Proton Bridge IMAP. Accounts are named; each has its own generated Himalaya config.
- Himalaya v2.2.1, rev `5b12b2a8c2c253b98f15c46610ad74cba2a182bc`.
  - Official asset: tgz sha256 `5c5ba272…65a0`, binary sha256 `03b5b077fa5227700a9196271ef1e7d053eb92eadbc535258a80762daddf5cb3` (V).
  - The IMAP-only build is `85d0cb1b…a810` or `dcbb5c07…faca`. The two differ only in the order of the feature names (V).
- Direct dependencies: the Go MCP SDK `github.com/modelcontextprotocol/go-sdk v1.8.0` and `github.com/google/jsonschema-go`, which the SDK already pulls in and which builds the input schemas. `go 1.26` or newer is needed for `new(expr)`, `os.Root` and `http.CrossOriginProtection`.

## 2. Tools

Named input types carry their constraints through `jsonschema.ForOptions.TypeSchemas`, so every tool gets them without edits per tool. Handlers re-validate every value, because the schema is documentation, not the boundary.

| type | JSON | rule |
|---|---|---|
| account | string | enum of the configured account names |
| mailbox, label | string | 1..255 code points and at most 1000 bytes. No C0, DEL or C1 characters, bidi controls, zero-width or tag characters (the set section 9 removes from mail text), no leading `-`. A case-insensitive `inbox` becomes `INBOX`. |
| uidvalidity | integer | 1..4294967295 |
| uid | integer | 1..4294967294. 4294967295 would mean `*` to Himalaya (V). |
| uids | []uid | 1..50 items, unique |
| address | string | Bare addr-spec, at most 254 bytes. `mail.ParseAddress(s)` must round-trip with an empty name. No leading `-`. Display names are not accepted. |
| file | string | A basename: no `/`, `\`, NUL or control characters, does not start with `.` or `-`, at most 200 bytes |
| date | string | `YYYY-MM-DD`, parsed with `time.Parse` |
| text | string | subject: at most 255 code points and 998 bytes, no control characters. body: at most 256 KiB, no NUL, no C0 except `\t\n\r`. search terms: 1..200 code points, no control characters. |

**Mailbox identity.** A mailbox name is addressable only if it passes the mailbox rule and the section 9 sanitizer leaves it unchanged. One predicate backs both: the mailbox rule refuses every character the sanitizer removes. Inputs must be addressable, and list_mailboxes returns exact names, omits the others and counts them in `omitted_unsafe_names`. Showing a cleaned name instead made `Folders/Review` and `Folders/Review` plus U+200B look like one folder, and calls with the listed name silently addressed the plain one. The same rule covers role mailboxes, `protected_mailboxes` and `label_prefix` in the config. To use an omitted folder, rename it in the mail client.

**Prefix P.** Every call starts with `himalaya -c <state>/himalaya/<acct>.toml -a <acct> -b imap --log-level off`. `--json` is added for every command except `message compose|reply|forward`. User values appear only as `--opt=value` or after `--`.

**Summary** (one row of a list or search):

```
{uid, message_id, date, from:[{name,email}], to:[…], subject, flags:[seen|answered|flagged|draft|deleted], has_attachment, size}
```

**Hints.** All four annotations are set explicitly on every tool. `openWorldHint` is always false, because the tools only touch the configured mailboxes and never fetch URLs.

- R: `readOnly:true, destructive:false, idempotent:true`.
- W: `readOnly:false, destructive:false` (additive only). `idempotent` is as listed per tool.
- D: `readOnly:false, destructive:true, idempotent:false`, except where marked. Anything that removes state (a flag, a location, a label) is D.

| tool | input (all take `account` except list_accounts) | argv after P, in order | output | hints |
|---|---|---|---|---|
| list_accounts | none | none (served from config) | `{accounts:[{name,email,mailboxes:{inbox,drafts,sent,trash,archive,junk},labels}]}` | R |
| list_mailboxes | none | `--json mailbox list --counts` | `{account,mailboxes:[{name,role,kind:system\|folder\|label,total,unread,movable}],omitted_unsafe_names}` | R |
| list_messages | mailbox, page 1..10000 (default 1), page_size 1..50 (default 20) | `imap status -- <mb>`, then `envelope list --mailbox=<mb> --page=<p> --page-size=<s> --has-attachment` | `{account,mailbox,uidvalidity,total,unseen,page,page_size,messages:[Summary]}` | R |
| search_messages | mailbox, from, to, subject, body, since, before, on, unseen, flagged, page, page_size. At least one criterion. | `imap status -- <mb>`, then `envelope search --mailbox=<mb> --page=<p> --page-size=<s> --has-attachment -- <query>` | same as list_messages, without total and unseen | R |
| read_message | mailbox, uidvalidity, uid, max_bytes 1024..262144 (default 32768) | status, size, then `message read --mailbox=<mb> -- <uid>` | `{account,mailbox,uidvalidity,uid,message_id,date,from,to,cc,reply_to,subject,body,body_format:text\|html_stripped\|none,truncated}` | R |
| list_attachments | mailbox, uidvalidity, uid | status, size, then `attachment list --mailbox=<mb> -- <uid>` | `{…ref, attachments:[{part_id,filename,mime,size}]}` (inline parts excluded) | R |
| download_attachment | mailbox, uidvalidity, uid, part_id 1..100000 | status, size, then `attachment download --mailbox=<mb> --dir=<fresh tmp> -- <uid> <part_id>` | `{file,size,sha256,mime}` | W, idempotent:false |
| update_flags | mailbox, uidvalidity, uids, seen?, flagged? (at least one) | status, fetch, `flag add\|remove --mailbox=<mb> --flag=seen\|flagged -- <uids>` (at most 2 calls), status | `{updated}` | D, idempotent:true |
| move_messages | mailbox, uidvalidity, uids, to | status(to), status, fetch, `message move --from=<mb> --to=<to> -- <uids>`, status | `{moved,from,to}` | D |
| archive_messages | mailbox, uidvalidity, uids | as move_messages, with `to` = the archive role | `{moved,from,to}` | D |
| trash_messages | mailbox, uidvalidity, uids | as move_messages, with `to` = the trash role | `{moved,from,to}` | D |
| restore_messages | uidvalidity, uids, to (default: inbox role) | as move_messages, with `from` = the trash role | `{moved,from,to}` | D |
| add_label | mailbox, uidvalidity, uids, label | status, fetch, `message copy --from=<mb> --to=<label> -- <uids>`, status | `{labeled}` | W, idempotent:true |
| remove_label | label, uidvalidity, uids | status, fetch, then `message delete --mailbox=<label> -- <uids>` run with `-c` pointing at the per-call config from section 2.2, then status | `{unlabeled}` | D, idempotent:true |
| create_draft | to, cc, bcc ([]address, at most 50 each), subject, body, attachments ([]file, at most 10) | `imap status -- <drafts>`, then `message compose [--to=a]… [--cc=]… [--bcc=]… [--subject=s] [--attach=<staged>]…` (body on stdin), then `--json message add --mailbox=<drafts> --flag=draft --flag=seen` (compose's stdout on stdin) | `{account,mailbox,uidvalidity,uid,message_id}` | W, idempotent:false |
| update_draft | uidvalidity, uid (in drafts), then the same fields as create_draft | status(drafts), fetch(uid), compose, add, `message move --from=<drafts> --to=<trash> -- <uid>` | `{…new ref, message_id, previous_trashed:"yes"\|"no"\|"uncertain", error?}` | D |
| reply_draft | mailbox, uidvalidity, uid, body, to?, cc?, attachments? | status(mb), size, status(drafts), `message reply --mailbox=<mb> [--to=]… [--cc=]… [--attach=]… -- <uid>` (body on stdin), status(mb), add | `{…ref,message_id}` | W, idempotent:false |
| forward_draft | mailbox, uidvalidity, uid, to?, cc?, body?, attachments? | status(mb), size, status(drafts), `message forward …` (same flags as reply), status(mb), add | `{…ref,message_id}` | W, idempotent:false |

How a few steps work:

- **fetch** is `--json imap fetch --mailbox=<mb> --flags --size -- <u1,u2,…>`. It reads only UID, FLAGS and RFC822.SIZE; a missing UID is simply absent from the output (V).
- **size** is the same fetch for one UID. Himalaya loads the whole raw message into memory and writes whole attachments before the wrapper sees any output (`src/imap/backend.rs:222`, `src/shared/attachment/download.rs:91`, V). Every body-fetching step (read, attachment list and download, reply, forward) therefore first requires `RFC822.SIZE <= limits.max_message_bytes` (default 25 MiB), else `too_large` with nothing fetched. The check takes the size from the row of the requested UID that carries RFC822.SIZE, because the output can also hold unsolicited FETCH rows (FLAGS only, possibly for other UIDs). Unless exactly one such row exists, the call fails with `mail_error` before any body fetch. A UID's content never changes within one UIDVALIDITY epoch, so the check cannot go stale. A missing UID gives `not_found`.
- **Search query:**
  - Patterns go in double quotes with `\` and `"` escaped.
  - `since D` becomes `after D-1`, `before D` becomes `not after D-1`, and `on D` becomes `date D`.
  - `unseen` becomes `not flag seen` (or `flag seen` when false), and `flagged` becomes `flag flagged`.
  - Clauses are joined with ` and `, and ` order by date desc` is always appended (V).
  - The criteria match the `Date:` header, not INTERNALDATE.
- **Capability gate:** before the first mutation on an account, the wrapper runs the fixed literal `--json imap raw -- 'A1 CAPABILITY'` once. If `MOVE` or `UIDPLUS` is missing, the call fails with `server_unsupported`. Without them, Himalaya leaves `\Deleted` copies behind (V). The result is cached per process once it succeeds.

### 2.1 Policy, enforced before any subprocess

- **Roles come from the wrapper config.** The generated Himalaya config has no `mailbox.alias` table. For IMAP, `resolve_mailbox` and `resolve_mailbox_id` then pass names through verbatim (V, `src/account/context.rs:237`, `src/shared/client.rs:545`). That removes alias shadowing, where a real folder whose name equals an alias key could not be addressed.
- **Protected mailboxes** are `protected_mailboxes` (default `All Mail`, `Starred`, `Scheduled`, `Recovered Messages`). They are never a move or label source or target. Names are compared case-insensitively.
- **Move targets** exclude protected mailboxes, the drafts and sent roles, and anything under `label_prefix`. On Bridge a MOVE into a label is a copy.
- **Sources:** messages in drafts or sent can only go to trash. `from == to` is refused. trash_messages refuses a trash source, and restore_messages refuses a trash target.
- **Labels** are enabled only when `label_prefix` is set. Set it only for servers where expunging from a label mailbox removes the label and keeps the message, which today means Bridge (`Labels/`).
  - A label must start with the prefix and be longer than it.
  - Moving out of a label mailbox is allowed. On Bridge the message lands in the target and loses that label; the tool description says so.
- **APPEND** goes only to the drafts role. On Bridge, an APPEND to INBOX or Sent is an import.

### 2.2 remove_label

Himalaya v2.2.1 has no shared command that removes one UID from one mailbox. The one UID-scoped removal it has is `message delete` inside the trash role, which sends `UID STORE +\Deleted` and then `UID EXPUNGE <uid>` (V).

1. For each call, the wrapper writes `<state>/tmp/<rand>/<acct>.toml`. It is the account config plus `mailbox.alias.trash = "<label>"`. Alias values are plain strings with no shell expansion (`src/config.rs:408`, V).
2. It passes the label byte-identically as `--mailbox=`.
3. It requires the output `{"action":"deleted","count":len(uids)}`. Anything else, including `moved-to-trash`, is `outcome_uncertain`.

Stray `\Deleted` messages are never expunged. On Bridge only the label goes away (V, from Bridge source). Real-Bridge acceptance is still open.

### 2.3 Not exposed

None of the following is reachable:

- Sending: `message send`, and `--send` on any command.
- Saving: `--save` and `--no-save`. Drafts use `message add` instead, which returns a UID and sets `\Draft`.
- Fields: `--from`, `--body`, `--body-file`, `--signature*`, `--seen`, `--raw`, `--log-file`.
- Commands: `flag set`, `message delete` outside section 2.2, `message copy` outside add_label, and every `imap` subcommand except `status`, `fetch` and the literal CAPABILITY probe.
- Mailbox management: create, delete, rename and subscribe.
- `smtp`, `sieve`, `jmap`, `gmail`, `msgraph`, `pimdir`, `maildir`, `mbox`, `configure`, `account check` as a tool, `manual`, `completion`, `json-schema`.
- Any free-form argv, path, URL or query string.

Mailbox create is left out because Bridge CREATE makes real Proton folders and labels. The owner creates them in Proton web.

### 2.4 Limitations and the simplest answer to each

| limitation | answer |
|---|---|
| No reply-all | The agent passes `cc` explicitly after reading the message. |
| Forward drops the source's attachments | Call download_attachment, then pass the files in `attachments`. |
| Bridge drafts lose In-Reply-To, References and Reply-To, so threading breaks | Document it. IMAP cannot fix it. |
| No in-place draft edit | update_draft adds the new version and moves the old one to Trash, where it stays recoverable. |
| A moved message gets a new UID that is not reported | The output says so. The agent re-lists the target. |
| No record of a trashed message's original folder | restore_messages takes `to`, defaulting to the inbox. |
| Paging follows arrival order, and search has no total | Document it. Totals come from `imap status`. |
| Without SORT, a search fetches the envelope of every hit | Require at least one criterion. The call timeout bounds the cost. |
| No cc, bcc or size search | Not offered. |
| Attachment filenames over 255 bytes abort the download | Clear `attachment_unsupported` error. Fix upstream, or later decode the part from `message read --json`. |
| `\Answered` and `\Draft` are local to Bridge | Only seen and flagged are writable. |
| Composed Message-IDs end in the hostname | Run the wrapper on a host or container with a neutral hostname. |

## 3. Message identity and stale references

- **Format.** A reference is `{account, mailbox, uidvalidity, uid}`. Batch tools take `uids` within one mailbox, and lists return `uidvalidity` once. Within one UIDVALIDITY epoch an IMAP server never reuses a UID, so a reference can never silently point at another message. UIDVALIDITY is not unique across accounts; the account is pinned by the per-account config file, not by the number.
- **Status before list.** `list_messages` and `search_messages` call `imap status` before the envelope command. If UIDVALIDITY changes in between, the returned references carry the old value and every later check rejects them. The opposite order could pair new UIDs with the new value, and nothing would catch it. The order is therefore fixed. The same applies to drafts: status of the drafts mailbox runs before `message add`.
- **Check before use.** Every tool that takes a reference first runs `imap status -- <mailbox>`.
  - A different `uid_validity` gives `stale_reference`.
  - `uid >= uid_next` gives `not_found`.
- **Existence before mutation.** Mutations also run fetch and fail with `not_found`, listing the missing UIDs, if any are absent. It is all or nothing. This is required because `flag add` on a missing UID exits 0, and move reports "No message moved" with exit 0 (V).
- **Target before move.** The move tools run `imap status -- <to>` first, before the source checks, so a missing target is a definite `mailbox_not_found` with nothing moved. Without it, the MOVE's own `Mailbox doesn't exist` failure is a failed mutating command and would be `outcome_uncertain` (section 6). Running it first keeps the window between the source checks and the move as short as before.
- **Render-time recheck.** reply_draft and forward_draft run the source reference check again after Himalaya renders the draft and before `message add`. A changed UIDVALIDITY gives `stale_reference`, and a failed status gives its own error. Either way nothing is appended, because the rendered draft may quote an unrelated message.
- **Count check.** The result `^(\d+) messages? successfully (moved|copied)$` must equal `len(uids)` (wording V, `src/shared/message/{mv,copy}.rs:49-51`). Otherwise the result is `partial`, with the count.
- **Status after mutation.** After the mutation, status runs again. If UIDVALIDITY changed, the result is `outcome_uncertain`.
- **Residual race, not closed.** The window lies between the check and the mutating subprocess's own SELECT: one Himalaya start plus login, about 20 ms on the fixture (V) and more on Bridge.
  - A UIDVALIDITY reset inside that window lets the mutation hit whatever message holds that UID in the new epoch. The design review reproduced it: Himalaya ran `UID MOVE` although its own SELECT reported a new UIDVALIDITY.
  - Stock v2.2.1 cannot make a UID command conditional on UIDVALIDITY, and the wrapper will not speak raw IMAP or patch Himalaya. The simplest real fix is upstream: an expected-UIDVALIDITY option checked after SELECT. Propose it to pimalaya.
  - Mitigations: the post-check reports `outcome_uncertain` naming the mailbox; every exposed mutation is reversible (flags, moves, trash, labels; no permanent deletion); Bridge resets UIDVALIDITY only on resync events, never on restart (V).
  - Concurrent moves by another client produce `not_found` or `partial`, never a wrong message.
  - Test: the argv shim runs a test-only hook that changes UIDVALIDITY just before a mutating exec, and the call must return `outcome_uncertain`.

## 4. No-send enforcement

| layer | mechanism | proven by (section 11) |
|---|---|---|
| L1 tool list | The 18 tools above. None sends, queues, forwards automatically, sets an autoresponder or filter, expunges broadly, or accepts argv, paths, URLs or raw queries. | `TestToolList` |
| L2 typed argv | One builder function per allowlisted command in `internal/himalaya`. Subcommand names and flag names are Go constants spelled out in full, because clap accepts prefixes. `-b imap` is fixed. Values go only into `--opt=value` or after `--`. | unit argv table |
| L3 runner guard | `Runner.Run` checks the fixed global prefix exactly, then looks the command path up in a positive table: `{account list, mailbox list, envelope list, envelope search, message read, message move, message copy, message compose, message reply, message forward, message add, message delete (only with a per-call label config), attachment list, attachment download, flag add, flag remove, imap status, imap fetch, imap raw}`. Each entry lists the exact long options it may carry (parsed as `--name` or `--name=value`) and whether positionals after `--` are allowed. Everything else is refused: unknown options, short options, any option on the wrong command (so `--from` is accepted only on move and copy, and `--send`, `--save`, `--no-save`, `--body*`, `--signature*`, `--seen`, `--raw`, `--log-file` are on no list), positionals before `--`, and `imap raw` unless the whole argv equals the CAPABILITY literal. A refusal is `internal` and is logged. | unit test, argv shim audit |
| L4 Himalaya config | A generated TOML per account containing an `imap` block only. It has no smtp, sendmail, jmap, gmail, msgraph, pimdir, sieve or local-store block, and no signature, downloads-dir or alias. At startup, `account list` must return exactly that account with `backends == ["imap"]`; this makes no connection and runs no secret command (V, designer strace). With no smtp block, every send path stops with "No send-capable backend" before any APPEND (V). | golden TOML, `TestSendPathsFailClosed` |
| L5 IMAP-only binary | Production runs the `imap,rustls-ring` build. Submission, Sieve and Gmail-settings code is absent (V). At startup the binary's sha256 must equal `himalaya.sha256`, and `--version` must report `v2.2.1` with rev `5b12b2a8…`. The feature set, compared as a set, must be exactly `{imap, rustls-ring}`, unless `allow_send_capable_build: true` is set (tests with the official asset only). | `TestStartupRefusals` |
| L6 Bridge semantics | The IMAP side of Bridge has no SendDraft (V). The wrapper adds only to Drafts and never moves into Sent, Drafts, Scheduled or All Mail. | policy unit tests |

Client-side approval of non-read-only tools is extra defence only; none of the layers above depends on it. Bridge's SMTP port accepts the same password as IMAP (V). The wrapper never connects to SMTP, and a deployment should keep the wrapper's process from reaching that port.

## 5. Configuration

**Format.** One JSON file, read with stdlib `encoding/json` and `DisallowUnknownFields`, so a typo fails at startup instead of being ignored as Himalaya ignores unknown account keys (V). Example for Proton Bridge:

```json
{
  "himalaya": {"path": "/opt/himalaya-mail-mcp/himalaya",
               "sha256": "85d0cb1bf08727dd3674dad5ad787df7693fb0cbee84fb1e82b4d66fd183a810"},
  "state_dir": "/var/lib/himalaya-mail-mcp",
  "call_timeout_seconds": 25,
  "http": {"listen": "127.0.0.1:8765",
           "token_file": "/etc/himalaya-mail-mcp/secrets/http-token"},
  "accounts": {
    "proton": {
      "email": "you@proton.me",
      "imap": {"host": "127.0.0.1", "port": 1143, "security": "starttls",
               "tls_cert_file": "/etc/himalaya-mail-mcp/bridge-cert.pem",
               "password_file": "/etc/himalaya-mail-mcp/secrets/proton.password"},
      "mailboxes": {"inbox": "INBOX", "drafts": "Drafts", "sent": "Sent",
                    "trash": "Trash", "archive": "Archive", "junk": "Spam"},
      "protected_mailboxes": ["All Mail", "Starred", "Scheduled", "Recovered Messages"],
      "label_prefix": "Labels/",
      "files_dir": "/var/lib/himalaya-mail-mcp/files/proton"
    }
  }
}
```

**Defaults and validation.**

- `mailboxes` and `protected_mailboxes` default to the Bridge values shown. `label_prefix` defaults to empty, which disables the label tools. `limits.max_attachment_bytes` defaults to 25 MiB; tests lower it. `allow_send_capable_build` defaults to false.
- Account names match `^[a-z][a-z0-9-]{0,31}$`, and `default` is refused.
- `security` is `tls` (`imaps://host:port`) or `starttls` (`imap://host:port` plus `starttls = true`). There is no cleartext option, because Himalaya would send credentials in the clear (V).
- `host` matches `^[A-Za-z0-9.-]{1,253}$`.
- Paths must be absolute and already clean, and contain no `$`, `~` or `:`. Himalaya shell-expands config paths and usernames and splits `-c` on `:` (V). The same rule covers `email`.
- `files_dir` must be distinct per account and not nested inside another account's.
- `state_dir` must already exist. `state_dir`, every `files_dir` and the directory of every secret file must be real paths with no symlink component. `os.OpenRoot` follows symlinks in the root path itself, so a lexical check alone let a `files_dir` that aliased the secrets directory pass, and a password file could then be attached by its basename. With symlinks refused, the lexical overlap and containment checks hold for the paths that are actually opened. For these checks the HTTP TLS certificate counts as a secret file.
- If `listen` is not loopback, both `allowed_hosts` and TLS are required.

**Generated Himalaya config.** The wrapper writes `<state>/himalaya/<acct>.toml` (mode 0600, directory 0700) at every start. Strings are TOML basic strings with `\` and `"` escaped; validation has already removed control characters.

```toml
[accounts.proton]
default = true
email = "you@proton.me"
imap.server = "imap://127.0.0.1:1143"
imap.starttls = true
imap.tls.cert = "/etc/himalaya-mail-mcp/bridge-cert.pem"
imap.sasl.plain.username = "you@proton.me"
imap.sasl.plain.password.command = ["/bin/cat", "/etc/himalaya-mail-mcp/secrets/proton.password"]
```

Why generate instead of accepting user TOML:

- v2.2.1 silently ignores unknown account keys.
- It shell-expands strings.
- Any config may hold a `password.command` that runs through `sh -c`, or blocks for smtp, signature or downloads-dir.
- Validating arbitrary TOML would need a TOML dependency and could still miss keys.

Generating from typed fields means every key is known. One file per account means only that account's secret command ever runs (V).

**Credentials.**

- `password_file` must be a regular file and not a symlink (checked with `os.Lstat`), owned by the service UID, with `mode&0o077 == 0`. It lives outside the repo and outside any directory that tools touch.
- The wrapper never reads the file. Himalaya runs the argv-form command `/bin/cat <path>`, with no shell and no expansion (pimalaya-config `command.rs`, V) and takes the first line. The secret therefore never appears in argv, env, the wrapper's memory, tool results or logs.
- If cat fails, Himalaya copies cat's stderr (a path, not the secret) into the error, and that error is never forwarded anyway.
- Bridge's `cert export` also writes `key.pem`. Delete it and give the wrapper only `cert.pem`.
- `tls_cert_file` must not be group- or world-writable. Actual trust policy (pimalaya-stream 0.3.0 `stream.rs:266,483`, V): a server leaf byte-identical to the configured certificate is accepted without hostname or expiry checks; anything else falls back to platform verification with the configured certificate added as an extra trust anchor, with normal hostname checks. With Bridge's self-signed CA-marked leaf this also accepts a different leaf signed by Bridge's key, which only the holder of that key can mint, so the wrapper must never receive Bridge's `key.pem`. It is a pin plus anchor, not an exclusive pin.

**HTTP token.**

- `token_file` follows the same rules as `password_file`. The token is at least 32 bytes of printable ASCII, read once at startup; rotating it requires a restart.
- Verification is `sha256` followed by `subtle.ConstantTimeCompare` inside `auth.RequireBearerToken` with `AllowMissingExpiration: true` (V). `TokenInfo.UserID` is `"service"`.
- It is the only credential the wrapper checks on HTTP. It authenticates the calling service and carries no user identity; any per-user authorization belongs to the client in front of the wrapper.

**Startup order.** Load and validate the config. Check the binary (regular file, not group- or world-writable, matching sha256) and every secret file's mode and real path. Check that `state_dir` and each `files_dir` are real paths; a `files_dir` that does not exist yet is checked up to its nearest existing ancestor. Nothing on disk changes before these checks pass: `os.Lstat(state_dir)` follows symlinked ancestors, so a refused `state_dir` through an alias used to have its `tmp/` emptied and the TOMLs written through the alias first. Then create `<state>/{himalaya,home,tmp}` with mode 0700 and an empty `tmp/`, and write each account's TOML. Create each `files_dir`, check it again, open it with `os.OpenRoot` and keep the handle for the life of the process. Only then run `--version` and `account list` per account, so every path check comes before the first Himalaya run. Then start the transport.

## 6. Subprocess runner (`internal/himalaya/runner.go`)

- `exec.Command(cfg.Himalaya.Path, argv...)` with an absolute binary path and an argv slice. There is never a shell.
- `cmd.Env` is fixed: `PATH=/usr/bin:/bin`, `HOME=<state>/home`, `XDG_CONFIG_HOME=<state>/home/.config`, `TMPDIR=<state>/tmp`. Nothing else is inherited. That excludes `SSL_CERT_*`, `*_proxy`, `RUST_LOG`, `RUST_BACKTRACE` and `HIMALAYA_CONFIG` (V). `cmd.Dir` is `<state>/home`.
- **Stdin** is always explicit: the body bytes, or nil, which means `/dev/null`. The MCP stdio stream never reaches the child.
- **Process group and cancellation.** The child runs with `SysProcAttr{Setpgid: true}`. A goroutine waits for the leader with `waitid(P_PID, pid, WEXITED|WNOWAIT)`, which does not reap it. When the leader exits, the context ends or stdout overflows, the runner sends SIGKILL to `-pid`, which also kills an orphaned secret command (V), then waits for the leader and calls `cmd.Wait`, with `cmd.WaitDelay = 1s`. The group is killed only while the leader is still unreaped, so a reused PGID is never targeted.
- **Deadline.** Each tool call gets `context.WithTimeout(call_timeout)`, 25 s by default and at most 280 s. That stays under the common 30 s client call timeout. Every subprocess in the call shares the deadline. Himalaya's own 60 s read stall never decides the outcome.
- **Output limits.**
  - stdout is capped at 4 MiB by default, 48 MiB for `message read`, and 40 MiB for compose, reply and forward. On overflow the runner kills the process group and the result is `too_large`.
  - stderr is capped at 64 KiB, kept for classification only and never returned.
- **Concurrency.** A process-wide semaphore of 4 subprocesses, acquired with the context. Every subprocess opens its own IMAP session, `message compose` included (it fails with a connect error when IMAP is down, V), so each draft costs one compose session on top of its status and add sessions, and all of them count toward Bridge's limit. That does not keep a busy agent under Bridge's limit of 400 new connections a minute, since four slots at about 50 ms per step allow far more. I accept that, because Bridge closes the excess connections on accept, before any IMAP command, so nothing changes and the call fails as `account_unavailable`, or as `outcome_uncertain` when the refused connection was a mutating step's, since EOF is not a definite failure. A rate limiter can be added if it happens in practice.
- **Retries:** never.
- **Exit handling:**
  - 0: parse the JSON.
  - 1: parse the error JSON `{"error","sources"}`, or the plain-text `Error:` on stdout for raw commands (V, designer run), then classify it.
  - 2: clap usage error, which can only be a wrapper bug: `internal`.
  - Killed by the deadline or cancel: `timeout` or `cancelled`.
- **Error classification.** Server text appears in the report (after `IMAP APPEND failed: NO `, for example), so it can hold any word. Only the start of Himalaya's own top-level message (`error`, or the text after `Error: `; never `sources`) can make a failure definite, and each such prefix names a stage that ends before the first mutating command:
  - `invalid peer certificate`: `tls_failed`
  - `Secret command error`: `credential_unavailable`
  - `IMAP AUTHENTICATE ` or `IMAP LOGIN `: `auth_failed`
  - `connect ` with a source starting `Connection refused`: `account_unavailable`. Any other `connect ` failure gets the code but is not definite.
  - `IMAP SELECT failed`: `mailbox_not_found`, definite only for commands that select first (below)

  Anything else gets a best-effort code from lowercased substrings of `error` plus `sources` and is never definite:
  - `stream stopped responding`: `timeout`
  - `mailbox doesn't exist`: `mailbox_not_found`
  - `fetch returned no body`, `no attachment with id`: `not_found`
  - `filename too long`: `attachment_unsupported`
  - `connect`, `unexpected end of file`, `broken pipe`: `account_unavailable`
  - anything else: `mail_error`

  The TLS, credential and login codes come only from the prefixes. Matching substrings let a server that took an APPEND and then refused the UID lookup's SELECT with `Mailbox doesn't exist: Drafts-authentication` turn an uncertain draft into a definite `auth_failed`. Bridge's wording (gluon) is U for the substring codes; they only choose an error code and never make a failure definite.
- **Mutation uncertainty.** Any failure of a mutating subprocess (flag, move, copy, add, delete) is `outcome_uncertain`, including connection reset and EOF: the design review showed `Connection reset by peer` after the server had taken a complete APPEND, and Bridge can apply an action that IMAP reported as NO. The only definite failures are those that happen before any mutating command can be sent, recognised by the prefixes above: `tls_failed`, `auth_failed`, `credential_unavailable`, connection refused, and `mailbox_not_found` from SELECT. Clap usage errors are `internal`.
  The rule is applied per command. A refused SELECT is definite only for commands that SELECT before their first mutating command (move, copy, delete, flag add and remove). `message add` without APPENDUID runs APPEND, then SELECT and a Message-ID search, so a SELECT failure can follow a stored APPEND. For `message add`, only the failures that precede the APPEND are definite; everything else, `select failed` included, is `outcome_uncertain`.
- **Multi-step results.** Tools record completed steps. If a later step fails, the result says what already happened instead of failing as a whole: for example, update_draft whose trash step fails returns the new draft reference with `previous_trashed: "no"` or `"uncertain"` and the error code in `error`.
- **Tool error text** is `"<code>: <fixed sentence>"` plus safe context such as the mailbox name, missing UIDs or the moved count. It never contains Himalaya text. `outcome_uncertain` for drafts includes the composed Message-ID, which the wrapper reads from compose stdout with `net/mail.ReadMessage`, so the result can be checked in Drafts.
- **Logs** go to stderr through slog. They hold the tool name, account, command path, exit code, classification and duration. Argument values, bodies, stdout, stderr and Himalaya error text are never logged, because server and message text can appear in them.
- **Panics.** Every handler is wrapped by a generic `guard[In, Out]` that recovers a panic into `internal`, because the SDK has no `recover` and a panic would kill every session (V).

## 7. Attachments

**Download** (`download_attachment`):

1. `os.MkdirTemp(<state>/tmp, "dl-")` creates a fresh 0700 directory. Himalaya writes only there, and only one part per call.
2. Open the temporary directory with `os.OpenRoot` and require exactly one entry, which must be a regular file per `root.Lstat`. Open it and recheck with `f.Stat()`. The size must be at most `max_attachment_bytes`.
3. Create the destination in the account's `files_dir` root with `root.OpenFile(name, O_WRONLY|O_CREATE|O_EXCL, 0o600)`, then copy with `io.CopyN(limit+1)`. `os.Root` refuses symlink escapes and `O_EXCL` refuses existing paths, including dangling symlinks. On any error the partial file is removed.
4. The name is `<YYYYMMDD>-<8 random hex>-<safe>`. `safe` is the original filename mapped to `[A-Za-z0-9._-]`, with leading dots and dashes stripped, at most 80 bytes, and `attachment` when empty. Himalaya's own sanitizing is not relied on.
5. Remove the temporary directory with a deferred call. Startup also empties `<state>/tmp`.

The result returns only the bare file name. Paths are never returned or accepted. There is no tool that lists or reads `files_dir`. Files stay until the owner removes them; there is no scheduler.

**Attach to drafts:**

1. `attachments` holds file names from `files_dir`. These are either files from download_attachment or files the owner placed there.
2. The wrapper checks each name with `root.Lstat`: it must be a regular file and not a symlink. It opens it through the same root and checks `f.Stat()` again. The opened file must not be `os.SameFile` as any secret file checked at startup (the password files and, for http, the token and the TLS key and certificate, since the certificate may be a combined file that holds the key), else `forbidden`. This also catches hard links, which no path check can see. There are at most 10 files, and their total is at most `max_attachment_bytes`.
3. It copies each file into a fresh 0700 temporary directory under the same basename with `io.CopyN(limit+1)`, so the limit holds even if the file grows after `Stat`, then passes `--attach=<tmp>/<name>`. `--attach` is a repeated argument with no delimiter splitting (V, `compose.rs:59-61`). Himalaya follows symlinks and reads any path, so it only ever sees paths the wrapper staged.

## 8. Transports (`internal/httpapi`)

**stdio:** `server.Run(ctx, &mcp.StdioTransport{MaxLineLength: 4 << 20})`, with logs on stderr only. There is no authentication; trust comes from the process boundary.

**HTTP.** The handler is `mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{…})` with these options:

- `Stateless: true`, `JSONResponse: true`, `PropagateRequestCancellation: true`, `MaxRequestBodyBytes: 4 << 20`.
- It serves `/mcp` only; any other path gets 404.
- Without a session, GET and DELETE get 405. Stateless mode issues no session id.

Middleware, outermost first (V):

1. **Exact Host allowlist.** Compare `r.Host` to `allowed_hosts`, which defaults to the actually bound `host:port`. A mismatch gets 403. This also blocks `localhost:<port>`, which the SDK's own check allows. The SDK's loopback check stays on.
2. **`http.NewCrossOriginProtection().Handler`.** A cross-site `Sec-Fetch-Site` or a mismatched `Origin` gets 403. Requests without `Origin`, which is what server-to-server clients send, pass.
3. **`auth.RequireBearerToken`** with the static verifier. A missing, Basic or wrong token gets 401, including on an unauthenticated `initialize`.
4. The MCP handler.

`http.Server` settings: `ReadHeaderTimeout 5s`, `ReadTimeout 30s`, `WriteTimeout call_timeout+10s`, `IdleTimeout 60s`, `MaxHeaderBytes 32 KiB`. The default listen address is `127.0.0.1:8765`. `ListenAndServeTLS` is used when the cert and key are set (key file checked like a secret). On SIGTERM, `Shutdown` runs with a 10 s limit and in-flight subprocesses die with their contexts.

The SDK provides session handling, schema validation, body limits and cancellation propagation. The wrapper adds the Host allowlist, Origin protection, bearer authentication, TLS, timeouts, the panic guard and the per-call deadline. Stateless legacy clients cannot cancel, so only the deadline stops their calls.

## 9. Untrusted content

- **read_message** decodes the mail-parser JSON into a few structs; `Binary` and `InlineBinary` bodies stay as `json.RawMessage` and are dropped.
  - `body` is the first `text_body` part whose variant is `Text`. If there is none, it is the first `html_body` part of variant `Html` (or a `text_body` part that is `Html`), stripped to text.
  - The stdlib-only stripper drops `script`, `style`, `head` and comments, turns block tags and `<br>` into newlines, removes all other tags and attributes (so `src` and `href` disappear), applies `html.UnescapeString`, and collapses blank lines.
  - Raw HTML is never returned.
- **Sanitizing** applies to every string that comes from mail (body, subject, names, filenames, message_id):
  - CRLF becomes LF.
  - Removed: C0 except `\n\t`, DEL, C1, bidi controls U+202A..202E and U+2066..2069, zero-width characters U+200B..200F, U+2060..2064, U+FEFF, and tag characters U+E0000..E007F.
  - Truncation is at a UTF-8 boundary. Header fields are capped at 1000 bytes and the body at `max_bytes`, with `truncated` set.
  - Mailbox names are never cleaned for display. A name the sanitizer would change is not addressable and list_mailboxes omits it (section 2, mailbox identity).
- **Headers** are read from part 0: `from`, `to`, `cc`, `reply_to`, `subject`, `date` and `message_id`. Group addresses are flattened. Unknown variants are omitted. The exact key spellings are confirmed in the e2e tests, `reply_to` included (V, TestReadPath reads Cc and Reply-To from a seeded message).
- **No remote fetches.** The wrapper makes no outbound HTTP calls. Himalaya fetched nothing for the tracker newsletter: strace showed one `connect()`, to IMAP (V).
- **Content never drives behaviour.** No tool acts on links, headers or instructions in a message. Recipients come only from tool inputs, or from Reply-To or From for reply_draft, and a reply is still only a draft. The tool descriptions and the server `Instructions` state that message content is untrusted third-party data.
- **Reads never mark mail as read.** read, attachment, reply and forward use `BODY.PEEK[]` (V). list and search fetch ENVELOPE only. `--seen` is never passed.

## 10. Repo layout and tooling

```
cmd/himalaya-mail-mcp/main.go      flags, subcommands, signals, startup sequence
internal/config/                   JSON types, Load, Validate, file mode checks
internal/himalaya/                 toml.go (generator), runner.go, commands.go (typed argv builders
                                   plus output structs), query.go, errors.go
internal/mailmcp/                  server.go (registration, schemas, guard), tools_*.go,
                                   refs.go (status, fetch, post-check), policy.go, files.go, text.go
internal/httpapi/                  host allowlist, cross-origin, bearer, http.Server wiring
internal/e2e/                      //go:build integration: fixture.go, argvshim/, *_test.go, testdata/
scripts/fetch-himalaya.sh          official v2.2.1 into a new empty dir; verifies tgz and binary sha256
scripts/build-himalaya-imap-only.sh   IMAP-only v2.2.1 from the signed tag in a pinned Rust image
docs/DESIGN.md, README.md          README covers setup, security and recovery
```

**`fetch-himalaya.sh <new-empty-dir>`** downloads `https://github.com/pimalaya/himalaya/releases/download/v2.2.1/himalaya.x86_64-linux.tgz` with `curl -fsSL --proto '=https'` (URL U, asset name V) and checks it with `sha256sum -c` against `5c5ba272…`. It extracts only the `himalaya` member, which sits at the archive root (V), checks the binary against `03b5b077…`, and runs `env -i <dir>/himalaya --version`. It needs nothing beyond curl, tar and coreutils. `.cache/` stays gitignored.

## 11. Verification plan

Commands:

- `gofmt -l .` must print nothing.
- `go vet ./...`
- `go test -race ./...` runs the unit tests, with no Docker and no network.
- `scripts/build-himalaya-imap-only.sh .cache/himalaya-imap-only && HMCP_HIMALAYA=.cache/himalaya-imap-only/himalaya go test -race -tags integration -count=1 ./internal/e2e/` needs Docker. The full suite runs against the IMAP-only build, because that is the only build the wrapper accepts by default. Running it with `HMCP_HIMALAYA` pointing at the official asset (from `scripts/fetch-himalaya.sh`, with `allow_send_capable_build`) is an optional compatibility check.

**Unit tests**, one table each:

- config validation: unknown field, a bad account name or `default`, `$ ~ :` in a path, a relative path, a secret with mode 0644 or a symlink, a symlink in `state_dir`, a `files_dir` or a secret file's path, a `files_dir` to be created below a symlink, a missing `state_dir`, overlapping `files_dir`, non-loopback without TLS or hosts, a short token.
- golden TOML for tls, starttls and no-cert accounts, and for the per-call label config.
- argv builders: every tool's argv, including search escaping, `order by`, date arithmetic, the UID csv and `--` placement.
- runner guard: forbidden command paths and tokens are refused.
- output parsers on JSON captured from the real binary: envelope list, mailbox list, status, fetch, read (plain, HTML-only, inline image), attachment list, the move and copy strings, add, raw CAPABILITY, error JSON and the plain-text `Error:`.
- error classification and mutation uncertainty: connection reset or EOF on a mutating command is `outcome_uncertain`; multi-step tools report completed steps when a later step fails (fake runner); a refused SELECT is definite for move but `outcome_uncertain` for `message add`; server text holding each trigger word (`authentication`, `invalid peer certificate`, `secret command`, `connection refused`, `select failed`) in an APPEND, MOVE, COPY, STORE or EXPUNGE failure, or in the SELECT after an APPEND, is `outcome_uncertain` on every mutating command and gives a read no login, TLS or credential code; the size check ignores unsolicited fetch rows.
- mailbox identity: the mailbox rule refuses every character the sanitizer changes; list_mailboxes omits and counts names with zero-width, bidi or tag characters; handlers refuse them in mailbox, `to` and label.
- sanitize, HTML strip and UTF-8 truncation.
- the safe-name mapper (`../../evil.sh`, `/etc/passwd`, `-rf.txt`, Unicode, 300 bytes, empty).
- `files.go` against `t.TempDir`: symlink, dangling symlink, directory, oversize and a hard link to a secret file.
- runner against a helper binary: stdout cap, a deadline that kills a grandchild, the exact env, stdin delivery, exit codes 1 and 2.
- httpapi with `httptest`: Host, Origin, tokens of the wrong length and the wrong value, 401 before the body is read.

**Integration setup (`internal/e2e`):**

- **Certificates.** Go generates a P-256 CA and a leaf for `localhost`/`127.0.0.1`, a rogue CA, and a leaf with SAN `wrong.test`, using `crypto/x509`.
- **Container.** `docker run` uses the pinned Dovecot digest with `--cap-drop ALL --cap-add SYS_CHROOT`, `no-new-privileges` and mail on a tmpfs. The name is `hmcp-it-<hex>`, the label `hmcp-fixture=1`, and the ports `127.0.0.1::31143`/`::31993`.
  - Setup waits for `* OK`, then seeds through `docker exec -i doveadm save`.
  - Cleanup uses `t.Cleanup` plus a TestMain sweep of the names it created. `docker ps -a --filter name=hmcp-` must be empty afterwards.
  - Profiles are `bridge` (the default) and `nomove`, which advertises no MOVE or UIDPLUS.
- **Reset.** Read-only tests share one fixture. Each mutating test starts its own, which costs about 2 s.
- **Verification helpers.** `doveadm fetch 'uid flags'` and the `mail_log` lines in `docker logs` check state and blast radius.
- **Server under test.** The real binary is built with `-race` in TestMain. stdio runs through `mcp.CommandTransport`. HTTP runs `himalaya-mail-mcp http` on `127.0.0.1:0` and reads the bound address from stderr.
- **Argv shim.** The config's `himalaya.path` points at a test-built shim whose sha256 is pinned. The shim appends `{argv, env}` to `<shim>.log` and `syscall.Exec`s the real binary named in `<shim>.target`. After the run, TestMain asserts that every recorded argv passes the L3 allowlist and that every env equals the fixed set. It also fails if servers started but none of their runs was audited.
- **Process leaks.** `assertNoProcs(t, stateDir)` scans `/proc/*/cmdline` for the state dir after every test.

The test names below match the functions in `internal/e2e/*_test.go`.

| test | transport | proves |
|---|---|---|
| TestToolList | stdio | The exact set of 18 tool names, and the four hints per tool. Every schema has `additionalProperties:false`. An unknown tool gets -32602. An extra `cmd` argument is rejected. |
| TestReadPath | stdio | The Unicode folder is listed, INBOX is normalised, roles and kinds come from config. Paging with size 2 gives [6,5],[4,3],[2,1],[]. Search by Unicode subject, from, unseen and since/before boundaries works; `a" or from bjorn` matches nothing; a pattern containing `order by` works. The multipart/alternative tracker newsletter returns its text part (`body_format=text`) with nothing from its HTML part. An HTML-only message that the test seeds comes back with `body_format=html_stripped` and no tags, URLs or tracker attributes. Cc and Reply-To are read. The prompt-injection message comes back as plain data. Adversarial filenames are listed. Afterwards, doveadm shows every flag unchanged and there is no `flag_change`. |
| TestAccountIsolation | stdio | bob's list has none of alice's mailboxes. After doveadm gives bob's INBOX a distinct UIDVALIDITY (Dovecot derives it from the clock, so two fresh accounts can match), alice's reference used with account bob gives `stale_reference`. With bob's password file removed, bob gets `credential_unavailable` or `auth_failed` while alice keeps working. alice's generated TOML does not contain bob's paths. |
| TestMailboxIdentity | stdio | Of `Folders/Review` and `Folders/Review` plus U+200B, both created with doveadm, list_mailboxes lists only the plain one and reports `omitted_unsafe_names: 1`. The hidden folder's exact name gives `invalid_argument` with no Himalaya run, and the listed name addresses the empty plain folder. |
| TestTLS | stdio | Through the CA, through the pinned leaf, and over STARTTLS: ok. With no cert, a rogue CA, or the wrong SAN through the CA: `tls_failed`, with no password in the result. A server started with `SSL_CERT_FILE=<CA>` in its own env and an account without a cert still gets `tls_failed`. |
| TestAttachments | stdio | `../../evil.sh` is written into `files_dir` under a generated name with mode 0600 and the right bytes. A 300-byte name gives `attachment_unsupported`. A message over `max_message_bytes` (cap lowered) gives `too_large` before any body fetch, and an attachment over `max_attachment_bytes` writes nothing to `files_dir`. A symlink planted in `files_dir` is refused for attach. `<state>/tmp` is empty afterwards. |
| TestDrafts | stdio | create_draft: `\Draft \Seen` in Drafts, with To/Cc/Bcc/subject and the attachment filename correct. A CRLF subject is rejected. update_draft: new UID, old one in Trash, nothing expunged in Trash. reply_draft: `In-Reply-To` is set and the source flags are unchanged. forward_draft re-attaches a downloaded file. |
| TestMovesAndTrash | stdio | With a stray `\Deleted` in INBOX: trash, restore, archive, and move into the Unicode folder all succeed, and the stray message survives. `from==to`, Drafts, Sent and `Labels/*` targets are `forbidden`. update_flags sets seen and flagged. add_label copies. remove_label leaves a stray `\Deleted` in `Labels/Work` alone. On the `nomove` profile, a move gets `server_unsupported`. |
| TestStaleAndInvalidRefs | stdio | After `doveadm mailbox update --uid-validity`, read and move get `stale_reference` with no mail_log events. UID 999 gives `not_found` for flags and move (where Himalaya alone would report success). With the shim hook changing UIDVALIDITY just before the mutating exec, the call returns `outcome_uncertain`. UID 0, UID 4294967295, duplicate UIDs and a control character in a mailbox are rejected by the schema. A missing mailbox gives `mailbox_not_found`. A move to a missing target gives `mailbox_not_found` and no MOVE runs. With the hook changing UIDVALIDITY before `message reply`, reply_draft gives `stale_reference`, runs no `message add`, and Drafts is unchanged. |
| TestAdversarialInputs | stdio | `--send` as an address, a mailbox `-c/etc/passwd`, `$(id)` in a body and a search term, a CRLF in a mailbox, a zero-width space in every mailbox field (refused by the handler), `../x` as an attachment, and `"1,2"` as a uid are all rejected or kept literal. The shim log shows no extra argv. |
| TestSendPathsFailClosed | `docker run --rm --network none` | The binary, the server-generated config and its password file are mounted into a container with no network that also runs the Dovecot fixture. `message send`, `compose --send`, `add --mailbox=Drafts --send`, `reply --send` and `forward --send` all exit 1 with "No send-capable backend". Each probe logs in to IMAP once and fails before any APPEND or submission: Drafts, INBOX and Sent keep their counts and UIDNEXT, INBOX flags are unchanged, and mail_log has no events. With the IMAP-only binary, `smtp` and `sieve` exit 2. The official asset, when present, runs the same probes, which shows that the generated config alone (L4) fails closed. |
| TestStartupRefusals | `check` | A wrong sha256, the official binary without `allow_send_capable_build`, an unknown config field, a 0644 password file, a password file symlink, `$` in a path, a `files_dir` that is a symlink to the secrets directory, a `state_dir` below a symlinked ancestor, and a `files_dir` to be created below one each exit non-zero before any IMAP traffic. All but the feature-set case also refuse before any change on disk or Himalaya run; that one runs only `--version`, after state_dir is prepared. For the two symlinked-ancestor cases nothing is created, written or removed in the alias target. |
| TestFailuresAndCancellation | stdio + HTTP | A stopped container gives `account_unavailable`. A silent TCP listener with a 2 s timeout gives `timeout` after about 2 s. A client cancel after 300 ms returns promptly over stdio and over HTTP (2026-07-28 with propagation). No process survives in any of these. |
| TestHTTP | HTTP | 401 for no token, a wrong token and Basic. 403 for a bad Host or `localhost:<port>`, and for a cross-site Origin. 405 for an authenticated GET. 413 for an oversized authenticated body; an oversized unauthenticated body gets 401. 404 for another path. The SDK client over protocols 2025-06-18 and the latest runs list_messages and update_flags. |
| TestHarness | none | The harness itself, with the real Himalaya binary behind the shim: fixture seed data and profile, the doveadm helpers, the shim log and hook, certificate rejection, and cleanup. |

## 12. Open questions

1. Real-Bridge acceptance: remove_label (the trash-alias trick) and label semantics, the `Spam` name, APPENDUID on Drafts, the gluon error wording used for error codes, and that reads leave unread mail unread. All of it is read from Bridge source or tested on Dovecot only.
2. The residual UIDVALIDITY race in section 3 (detected afterwards, reversible, rare on Bridge). The real fix is an upstream expected-UIDVALIDITY option in Himalaya.
