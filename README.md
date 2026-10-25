# himalaya-mail-mcp

An MCP server with 18 typed mail tools for named accounts. Each step of a tool call runs the pinned Himalaya v2.2.1 binary with fixed argv and no shell. It cannot send mail, delete mail permanently or run arbitrary commands. The design record is [docs/DESIGN.md](docs/DESIGN.md).

```
MCP client (stdio, or HTTP + bearer) -> himalaya-mail-mcp -> himalaya (one process per step) -> Proton Bridge IMAP
```

Bridge handles Proton login, encryption and sync. The wrapper reaches it only through Himalaya's IMAP backend, over STARTTLS with Bridge's exported certificate. Accounts are named and isolated: each has its own generated Himalaya config, password file and `files_dir`, and logs in with an IMAP username and password.

## Tools

Every tool except list_accounts takes `account`. A message reference is `{account, mailbox, uidvalidity, uid}` from list_messages or search_messages. R is read-only, W adds state, D removes state (a flag, a location or a label).

| tool | what it does | hint |
|---|---|---|
| list_accounts | Accounts, role mailboxes and label settings, from config | R |
| list_mailboxes | Mailboxes with role, kind, counts and whether each can be a move target | R |
| list_messages | One page of a mailbox, newest arrivals first, with uidvalidity, total and unseen | R |
| search_messages | One mailbox by from, to, subject, body, Date-header dates, unseen or flagged | R |
| read_message | One message as sanitized text; HTML is stripped, never returned raw | R |
| list_attachments | Non-inline attachments with their part_id | R |
| download_attachment | Saves one attachment in the account's `files_dir` under a generated name | W |
| update_flags | Sets or clears seen and flagged | D |
| move_messages | Moves to another folder | D |
| archive_messages | Moves to the archive role | D |
| trash_messages | Moves to the trash role, where messages stay recoverable | D |
| restore_messages | Moves out of trash to `to`, default the inbox | D |
| add_label | Copies into a `Labels/` mailbox, which adds the label on Bridge | W |
| remove_label | Removes one label from the given UIDs; the messages stay in their folders | D |
| create_draft | Saves a new draft in Drafts | W |
| update_draft | Saves a new version, then moves the old one to Trash | D |
| reply_draft | Saves a reply as a draft; recipients default to Reply-To or From | W |
| forward_draft | Saves a forward as a draft, without the source's attachments | W |

Reads never mark mail read. Batch tools take up to 50 UIDs in one mailbox and change nothing unless every UID exists. Moved messages get new UIDs that are not reported, so list the target. There is no reply-all; pass `cc`. Bridge drops In-Reply-To, References and Reply-To from drafts, so replies are not threaded. Errors read `<code>: <sentence> (<detail>)` and never contain Himalaya or server text. list_mailboxes returns names exactly as the server has them; a mailbox whose name holds control, bidi, zero-width or tag characters is left out and counted in `omitted_unsafe_names`, and such names are refused as input. Rename it in the mail client to use it.

## What it cannot do

No tool, argument or argv path sends mail or submits over SMTP. None forwards automatically, sets an autoresponder, Sieve script or filter, deletes permanently, expunges broadly, creates or deletes mailboxes, or appends outside Drafts. None takes a free-form command, path, URL or raw IMAP string. Protected mailboxes (`All Mail`, `Starred`, `Scheduled`, `Recovered Messages`) are never a move or label source or target. The layers, each independent (DESIGN section 4):

1. The 18 tools, with closed input schemas and every value checked again in the handler.
2. One typed argv builder per allowed command; user values go only into `--opt=value` or after `--`.
3. A runner guard with a positive table of command paths and long options. Anything else, such as `--send`, `--save`, `--seen` or a short option, is refused before exec.
4. A generated Himalaya config with an `imap` block only. With no `smtp` block, every send path fails with "No send-capable backend".
5. The IMAP-only Himalaya build. The wrapper refuses a binary whose features are not exactly `imap,rustls-ring`, so SMTP, Sieve and Gmail code is absent.
6. Bridge itself: its IMAP side has no send call, and the wrapper appends only to Drafts.

Tool hints let a client ask for approval before non-read-only tools. None of the layers depends on that.

## Install

```sh
go install github.com/NoahHakansson/himalaya-mail-mcp/cmd/himalaya-mail-mcp@v0.1.0
```

This installs only the wrapper, into `$(go env GOBIN)` or `$(go env GOPATH)/bin`. It needs Go 1.26 or newer and runs on Linux.

Himalaya is a separate dependency that `go install` does not provide. The wrapper runs only Himalaya v2.2.1 (rev `5b12b2a8`), refuses any other binary, and by default accepts only the IMAP-only build described below, so build it from a checkout of the same tag:

```sh
git clone --branch v0.1.0 https://github.com/NoahHakansson/himalaya-mail-mcp.git
cd himalaya-mail-mcp
scripts/build-himalaya-imap-only.sh .cache/himalaya-imap-only
```

The script needs Docker and the Himalaya maintainer's gpg key (see [Himalaya binary](#himalaya-binary)). Then point `himalaya.path` and `himalaya.sha256` in the config at the built binary.

## Setup

Requirements: Linux x86_64, Go 1.26 or newer, Docker (to build Himalaya and run the integration tests), `/bin/cat` on the host or image, and Proton Bridge with IMAP reachable from the wrapper. From a checkout, `go build -o himalaya-mail-mcp ./cmd/himalaya-mail-mcp` builds the same binary as `go install`.

### Himalaya binary

Production uses the IMAP-only build from the signed v2.2.1 tag. The build script needs Docker and the Himalaya maintainer's key. Import the key first (`curl -fsSL https://github.com/soywod.gpg | gpg --import`; a throwaway `GNUPGHOME` works), then:

```sh
scripts/build-himalaya-imap-only.sh .cache/himalaya-imap-only
```

The script verifies the tag signature, fetches crates, and compiles with `--network none`. It prints the sha256 of `<dir>/himalaya`, which is `85d0cb1b…a810` or `dcbb5c07…faca`; the two differ only in feature-name order. Install it root-owned with mode 0755 (the wrapper refuses a group- or world-writable binary) and put its sha256 in `himalaya.sha256`.

For tests only, `scripts/fetch-himalaya.sh .cache/dl-v2.2.1/extract` downloads the official asset and checks the archive and binary digests. It is send-capable, so the wrapper accepts it only with `"allow_send_capable_build": true`. Never set that in production.

### Config

One JSON file, passed as an absolute path. Unknown fields stop startup. A complete minimal Bridge config:

```json
{
  "himalaya": {
    "path": "/opt/himalaya-mail-mcp/himalaya",
    "sha256": "85d0cb1bf08727dd3674dad5ad787df7693fb0cbee84fb1e82b4d66fd183a810"
  },
  "state_dir": "/var/lib/himalaya-mail-mcp/state",
  "http": {
    "listen": "127.0.0.1:8765",
    "token_file": "/etc/himalaya-mail-mcp/secrets/http-token"
  },
  "accounts": {
    "proton": {
      "email": "you@proton.me",
      "imap": {
        "host": "127.0.0.1",
        "port": 1143,
        "security": "starttls",
        "tls_cert_file": "/etc/himalaya-mail-mcp/bridge-cert.pem",
        "password_file": "/etc/himalaya-mail-mcp/secrets/proton.password"
      },
      "label_prefix": "Labels/",
      "files_dir": "/var/lib/himalaya-mail-mcp/files/proton"
    }
  }
}
```

Defaults and rules:

- `call_timeout_seconds` is 25 (1..280), one deadline shared by every Himalaya step of a call, so calls finish inside a typical 30 s client timeout.
- `limits.max_message_bytes` (25 MiB) stops larger messages from being fetched at all. `limits.max_attachment_bytes` (25 MiB) bounds each download and the attachments of each draft.
- `http.listen` defaults to `127.0.0.1:8765`. A non-loopback address requires `allowed_hosts` and TLS (`tls_cert_file`, `tls_key_file`). `allowed_hosts` defaults to the bound address and is matched exactly.
- `mailboxes` defaults to Bridge's names (`INBOX`, `Drafts`, `Sent`, `Trash`, `Archive`, `Spam` for inbox, drafts, sent, trash, archive, junk). `protected_mailboxes` defaults to the four listed above.
- An empty `label_prefix` disables the label tools. Set `Labels/` only for Bridge, where expunging from a label mailbox removes just the label.
- `security` is `tls` or `starttls`; there is no cleartext mode. Bridge uses STARTTLS on the first free port from 1143, so read the port from Bridge's `info`.
- Account names match `^[a-z][a-z0-9-]{0,31}$`, and `default` is refused.
- Paths are absolute and clean and contain none of `$ ~ : " \`. `state_dir`, each `files_dir` and the secret files have no symlink component. A `files_dir` must not overlap another, contain `state_dir`, or lie inside its `himalaya`, `home` or `tmp`. No secret file, the HTTP TLS certificate included, may sit under `state_dir` or a `files_dir`.

### Secrets and the Bridge certificate

- `password_file` holds the Bridge password (Bridge CLI `info <account>`) on its first line. Like every secret file it must be a regular file, not a symlink, owned by the service user, with mode 0600 or 0400. The wrapper never reads it: Himalaya runs `/bin/cat <path>` in each process, so the password never appears in argv, env, results or logs.
- `token_file` holds the HTTP bearer token, the only credential the wrapper checks on HTTP: at least 32 printable ASCII bytes, no whitespace, read once at startup. Create it with `umask 077; openssl rand -hex 32 > <token_file>`.
- `tls_key_file` follows the secret rules. `tls_cert_file` and the Bridge certificate must be regular files that are not group- or world-writable.
- Run `cert export` in the Bridge CLI. It writes `cert.pem` and `key.pem`. Copy only `cert.pem` to `imap.tls_cert_file`, then delete `key.pem`. The wrapper's user must never be able to read Bridge's key (see Security).

### Generated Himalaya config

Every start writes `<state_dir>/himalaya/<account>.toml` (mode 0600, directory 0700). Do not edit it. For the example:

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

remove_label adds a per-call copy with `mailbox.alias.trash` set to the label, under `<state_dir>/tmp`. Himalaya runs with `PATH=/usr/bin:/bin`, `HOME=<state>/home`, `XDG_CONFIG_HOME=<state>/home/.config`, `TMPDIR=<state>/tmp` and no other environment.

### Running

```sh
himalaya-mail-mcp -config /etc/himalaya-mail-mcp/config.json check   # startup checks, then a login per account
himalaya-mail-mcp -config /etc/himalaya-mail-mcp/config.json stdio   # MCP on stdin/stdout, no authentication
himalaya-mail-mcp -config /etc/himalaya-mail-mcp/config.json http    # Streamable HTTP on /mcp
```

- `check` probes CAPABILITY (MOVE and UIDPLUS are required) and prints `<account>: ok` or `<account>: FAIL <code>: <sentence>`, exiting 1 on any failure. It checks the HTTP secrets when `token_file` is set and leaves `<state>/tmp` alone, so it can run next to a live server.
- `http` logs `msg=listening addr=<host:port> tls=<bool>`. It serves only `/mcp`, stateless with JSON responses; GET and DELETE get 405. On SIGTERM it stops within 10 s and kills Himalaya processes still running.
- Logs are slog text on stderr: tool, account, command path, exit code, error class and duration, never argument values, bodies or server text.

### Files and identity

- Run it as its own user, with no access to Bridge's vault or key. Secret files are owned by that user with mode 0600 or 0400; the binary, config and certificates must not be writable by it or by others.
- `state_dir`: created beforehand, owned by the service user, 0700. The wrapper refuses one that is missing or group- or world-writable and creates `himalaya/`, `home/` and `tmp/` with 0700.
- One `files_dir` per account, owned by the service user, 0700. It is the only directory the agent writes into (through download_attachment, files 0600) and the only source of draft attachments; a hard link to a secret file is refused. Nothing lists or deletes it.
- A neutral hostname such as `mail-mcp`, because composed Message-IDs end in it.

## Security notes

- Mail content is untrusted. Bodies, headers, names and filenames lose control, bidi, zero-width and tag characters; HTML is reduced to text; nothing fetches remote content. Tool descriptions and server instructions tell the agent not to follow instructions in mail.
- TLS trust (pimalaya-stream 0.3.0): a server leaf byte-identical to `tls_cert_file` is accepted with no hostname or expiry check. Any other leaf goes through platform verification with `tls_cert_file` added as an extra trust anchor and normal hostname checks. Bridge's certificate is a self-signed CA, so a different leaf signed by Bridge's key also passes. It is a pin plus an anchor, not an exclusive pin, which is why the wrapper must never get `key.pem`. The fixed environment keeps `SSL_CERT_FILE` and similar variables from widening trust.
- UIDVALIDITY race: between the wrapper's status check and the mutating Himalaya process's own SELECT, a UIDVALIDITY reset would let the mutation hit whatever message holds that UID in the new epoch. Stock v2.2.1 cannot make a UID command conditional. Mitigations: the status check after each mutation reports `outcome_uncertain` when UIDVALIDITY changed, every exposed mutation is reversible, reply and forward recheck the source before saving, and Bridge resets UIDVALIDITY only on resync events, never on restart. The real fix is an upstream expected-UIDVALIDITY option.
- Bridge's IMAP password also works on Bridge's SMTP, which cannot be disabled. The wrapper never connects to SMTP; where it runs, its process should not be able to reach Bridge's SMTP port either.
- HTTP checks run in this order: exact Host allowlist (403), cross-origin protection (403 for cross-site browser requests; no `Origin` passes), then the bearer token compared as sha256 in constant time (401, also on an unauthenticated initialize). Bodies are capped at 4 MiB. stdio trusts whoever starts the process.
- At most 4 Himalaya processes run at once. Every step, `message compose` included, is its own IMAP login. Bridge closes new connections beyond 400 a minute on accept. That shows as `account_unavailable`, or as `outcome_uncertain` if it hits the mutating step itself.

## Recovery

- `outcome_uncertain`: a mutating step failed after its command may have reached the server, or UIDVALIDITY could not be confirmed afterwards. Do not retry. List the mailboxes named in the error first; for drafts the error carries the composed `message_id`, which list_messages on Drafts shows.
- `partial`: only some UIDs moved or were labeled; the detail has the count. `stale_reference`: a Bridge resync changed UIDVALIDITY; list again.
- Restore from Trash with list_messages on the trash mailbox, then restore_messages with `to`. The original folder is not recorded.
- update_draft with `previous_trashed` `no` or `uncertain` saved the new draft, but the old one may still be in Drafts; `error` says why. List Drafts and trash the old UID. If the new version failed, the error says the previous draft was left in place.
- Token rotation: write the new token to `token_file`, restart `http`, then update the client. Calls get 401 in between.
- Password rotation: replace `password_file`, keeping its owner and mode, and run `check`. No restart is needed, because each Himalaya process reads the file. Rotating the Bridge password itself may need a Bridge vault reset (unverified).
- Bridge certificate rotation: a new vault or `cert import` makes calls fail with `tls_failed`. Export again, install only the new `cert.pem`, delete `key.pem`, run `check`.
- Bridge updates: after an update, run `check`. A changed certificate shows as `tls_failed`, a changed port or password as `account_unavailable` or `auth_failed`. If Bridge's IMAP semantics changed in the release notes (labels, drafts, Trash), recheck the unverified Bridge behaviour listed below before relying on mutations.
- Himalaya upgrade: the version and rev are pinned in `internal/himalaya/runner.go`, so an upgrade is a code change. Re-verify argv, JSON output, error wording and send paths against the new release (DESIGN sections 2, 4 and 6), bump `REV`, `TAG` and the image in the build script, rebuild, update the pins and `himalaya.sha256`, run both test suites against the new IMAP-only build, then `check`.
- `files_dir` grows until you clean it, for example `find /var/lib/himalaya-mail-mcp/files -type f -mtime +30 -delete` as the service user. No restart is needed. `<state>/tmp` is emptied at every stdio or http start.
- A startup refusal exits 1 and logs `msg="startup failed" error="…"` naming the field; a usage error exits 2. Fix the named item, then run `check`:

| error contains | cause |
|---|---|
| `unknown field` | a typo or an unsupported key such as `smtp` |
| `does not match himalaya.sha256`, `binary is not himalaya v2.2.1`, `does not report rev` | wrong binary or hash |
| `are not exactly [imap rustls-ring]` | a send-capable build without `allow_send_capable_build` |
| `must be owned by uid`, `must not be accessible by group or others` | secret file owner or mode |
| `must be a regular file, not a symlink`, `must not be group- or world-writable` | binary, certificate or `state_dir` type or mode |
| `must be an absolute, clean path`, `must not contain $ ~ :`, `must not contain symlinks` | a path in the config, or an ancestor of a `files_dir` not created yet |
| `state_dir: lstat`, `no such file or directory` | a missing `state_dir` or secret file |
| `overlap`, `is inside`, `must not contain state_dir` | `files_dir`, `state_dir` and secrets mixed |
| `http.listen is not loopback`, `http.token_file is required`, `shorter than 32 bytes` | HTTP settings |

## Verification

```sh
gofmt -l .                                          # must print nothing
go vet ./... && go vet -tags integration ./internal/e2e/...
go test -race ./...                                 # unit tests, no Docker or network
go test -race -tags integration -count=1 ./internal/e2e/
HMCP_HIMALAYA=.cache/dl-v2.2.1/extract/himalaya go test -race -tags integration -count=1 ./internal/e2e/
```

The integration suite needs Docker and takes about 70 s. By default it uses `.cache/himalaya-imap-only/himalaya`; the last line runs it against the official asset. It builds the real server with `-race` and drives it with the Go MCP SDK client over stdio and HTTP, against disposable Dovecot containers (`hmcp-it-*`, bound to 127.0.0.1, removed afterwards) seeded with synthetic messages. A shim records every Himalaya run, and TestMain checks each argv against the runner guard and each environment against the fixed set. The 15 tests, listed in DESIGN section 11, prove:

- the exact tool list, hints and closed schemas, and that unknown tools or extra arguments never reach Himalaya
- reads that change no flags, paging, search escaping, Unicode folders, exact mailbox names, HTML stripping and account isolation
- certificate pinning and CA validation over TLS and STARTTLS, with no password in any failure
- attachment confinement and size limits, and drafts saved only to Drafts with `\Draft \Seen`
- moves, trash, restore, flags and labels that touch only the named messages and never expunge stray `\Deleted` ones; stale and missing references, including a UIDVALIDITY reset just before a mutation
- adversarial inputs that never become extra argv; live probes inside `docker run --network none` of `message send` and `--send` on compose, add, reply and forward, which fail closed; startup refusals before any IMAP traffic (hash, config, secret and path refusals also before any change on disk or Himalaya run; the feature-set refusal comes after state_dir is prepared and `--version` has run); timeouts and cancellation with no leaked processes; and the HTTP front door
- that `smtp` and `sieve` are unrecognized subcommands in the IMAP-only build. `smtp`, `sieve`, `jmap`, `gmail`, `msgraph` and `pimdir` are excluded structurally rather than probed live: the runner allowlist never builds them and the IMAP-only build leaves their code out

## Unverified against real Bridge

The integration suite runs against Dovecot with a Bridge-like capability set, and Bridge semantics were read from Bridge's source. On a running Bridge these are not yet confirmed:

1. `check` passes and reads leave unread mail unread.
2. add_label and remove_label add and remove only the label; remove_label relies on Bridge expunging from `Labels/` as an unlabel.
3. The `Spam` mailbox name, APPENDUID on Drafts, and gluon's error wording, which picks error codes (never whether a failure is definite).

The UIDVALIDITY race under Security notes is a known limitation, not a test gap.
