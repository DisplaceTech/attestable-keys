# attestable-keys

Public mirror **and** Cloudflare Pages deploy source for `https://keys.displace.tech` —
the published ed25519 signing keys for Attestable evidence packs, the machine-readable
key manifest, and the standalone offline verifier.

Normative spec: [`docs/SPEC_Attestable_Key_Publication.md`](../docs/SPEC_Attestable_Key_Publication.md)
(sibling repo in this checkout). This README summarizes and links back to it; the
spec wins on any conflict.

## Canonical vs. mirror — there is only one copy

Cloudflare Pages deploys **from this repository**. There is no separate "build the
site, then push to the mirror" step — the repo root *is* the site root. This is
deliberate (spec §8): it is structurally impossible for `keys.displace.tech` and
`github.com/DisplaceTech/attestable-keys` to diverge, because they are the same
bytes on the same branch. Git history here, GitHub's independent hosting, and the
OpenTimestamps proofs alongside each `.pub` file jointly establish "this key existed,
unchanged, since date X" without requiring anyone to trust Displace's server.

`main` is never force-pushed. Branch protection should be turned on (see ⚠️ HUMAN below)
before this repo is treated as load-bearing.

## Layout

```
index.html                      human page (spec §3) — zero JS, no external resources
keys.json                       machine manifest (spec §4)
keys.json.minisig               NOT YET COMMITTED — see "Placeholder slots" below
attestable-2026-a.pub           NOT YET COMMITTED — see "Placeholder slots" below
attestable-2026-a.pub.ots       NOT YET COMMITTED — see "Placeholder slots" below
verify.sh                       standalone verifier (spec §6)
verify.sh.minisig               NOT YET COMMITTED — see "Placeholder slots" below
revocations/.gitkeep            revocation notices land here, if/when issued (spec §7)
_headers                        Cloudflare Pages response headers (spec §3)
tests/                          fixture-based tests for verify.sh (not deployed)
```

### Placeholder slots (deliberately not committed)

Five files are named throughout this repo but do not exist yet:

- `attestable-2026-a.pub`
- `attestable-2026-a.pub.ots`
- `keys.json.minisig`
- `verify.sh.minisig`
- (later, if ever needed) `revocations/revocation-attestable-2026-a.txt`

All five require the real private key, which **does not exist in this repo, this
tooling, or this conversation** — it is minted offline by the operator per spec §2.
Nothing here generates a keypair, and no `.key`/`.pub` byte was fabricated to fill
these slots: an invalid or placeholder signature file would be actively worse than
a missing one, since `verify.sh` treats a present-but-broken `.minisig` as a hard
FAIL, not a SKIP. Until the real key is minted, `keys.json` and `index.html` both
say `pubkey_sha256: "PENDING-OFFLINE-MINT"` so the two can never quietly disagree.

**Do not deploy this repo as the live `keys.displace.tech` site until the first key
commit (below) is done.** Before that, the site would publish real-looking URLs
(`/attestable-2026-a.pub`, `/keys.json.minisig`, …) that 404 — worse than not
existing, since a pack's printed verification page tells a reviewer to fetch them.

## Operator runbook: first key commit

Do this once, offline, before the first evidence pack is ever delivered
(`RUNBOOK.md` §0 / spec §2 — commands reproduced verbatim from spec §2):

```bash
# Offline machine or airgapped-enough workstation session
minisign -G -p attestable-2026-a.pub -s attestable-2026-a.key \
  -c "Attestable signing key attestable-2026-a (Displace Technologies LLC)"
# Passphrase: required, generated, stored in password manager (separate from key file)

# Encrypt private key at rest; destroy plaintext
age -e -R ~/.age/recipients.txt -o attestable-2026-a.key.age attestable-2026-a.key
shred -u attestable-2026-a.key

# Record fingerprint (goes in keys.json, packs, and the human page)
sha256sum attestable-2026-a.pub

# External existence proof
ots stamp attestable-2026-a.pub        # → attestable-2026-a.pub.ots
# Run `ots upgrade attestable-2026-a.pub.ots` after ~24h; publish the upgraded proof
```

`attestable-2026-a` may be minted offline now, ahead of its `valid_from` date —
`created` (mint date) and `valid_from` (first date the key may actually be used to
sign a pack) are deliberately separate fields. This key's `valid_from` is
**2026-07-20**, gated on Tech E&O/cyber coverage binding (TDD Story 6); do not sign
a real evidence pack with it before that date even though the key material can
exist earlier. `valid_to` is **2027-07-20** (one year later) — see Rotation below.

Then, in this repo:

1. Copy `attestable-2026-a.pub` and the upgraded `attestable-2026-a.pub.ots` into the
   repo root.
2. Replace every `"PENDING-OFFLINE-MINT"` in `keys.json` and `index.html` with the
   real `sha256sum` output from above (lowercase hex).
3. Sign the manifest and the verifier with the new key and commit the sidecars:
   ```bash
   age -d attestable-2026-a.key.age > /tmp/k
   minisign -S -s /tmp/k -m keys.json -x keys.json.minisig \
     -t "attestable-2026-a keys.json $(date -u +%FT%TZ)"
   minisign -S -s /tmp/k -m verify.sh -x verify.sh.minisig \
     -t "attestable-2026-a verify.sh $(date -u +%FT%TZ)"
   shred -u /tmp/k
   ```
4. `git add attestable-2026-a.pub attestable-2026-a.pub.ots keys.json keys.json.minisig \
   verify.sh.minisig index.html && git commit` — this is the one commit in this repo's
   history that is manual and offline-key-dependent; every subsequent `keys.json`
   change follows the same re-sign step (see Rotation, below).
5. Run `verify.sh` against a real pack (see "Testing" below) before treating the
   deploy as live.

Private key custody note (spec §2): `.key.age` on the workstation plus one offline
backup medium; passphrase in the password manager only; the two are never stored
together. The plaintext key exists only in `/tmp` during a signing session and is
`shred -u`'d immediately after (RUNBOOK §5.4).

## Rotation & revocation

Policy text (published verbatim on `index.html`, spec §7):

> Keys are never reused. Each key is valid for one year from its `valid_from` date
> and is rotated on schedule at expiry; rotation also occurs early on suspected
> compromise, custody change, or major infrastructure change. On rotation, the
> outgoing key is marked `retired` with its validity window; signatures made
> within that window remain valid indefinitely. On compromise, the key is marked
> `revoked` in keys.json with a dated, reasoned revocation notice signed by the
> successor key; packs signed under a revoked key are re-issued under the
> successor on request at no charge. All keys ever published remain listed and
> their pubkey files remain available permanently.

Operational procedure (spec §7):

1. Begin minting the successor key **at least 30 days ahead of the active key's
   `valid_to`** — there is no grace period; a pack generated after `valid_to`
   with no successor active will FAIL the manifest check.
2. Mint the new key per §2 above (new `key_id`, e.g. `attestable-2027-a`).
3. Append the new key to `keys.json` as `"status": "active"`; set the predecessor's
   `status` to `"retired"` and fill in its `valid_to`.
4. Re-sign `keys.json` (and `verify.sh` if it changed) **with the new key**.
5. Commit — entries are append-only; never delete or rewrite a prior key's entry.
6. New evidence packs reference the new `key_id` from this point on.

Revocation additionally requires: write and sign `revocations/revocation-<key_id>.txt`
with the successor key, set `signatures_valid_before` in that key's `keys.json`
entry to the last provably-good date (or the compromise-discovery date if unknown),
and notify every customer holding a pack signed under the revoked key.

## `verify.sh`

Standalone POSIX `sh` verifier implementing the spec §6 contract: pin check →
manifest check (online only, via `-f`) → minisign signature checks → ledger chain
check → OpenTimestamps anchor check (if `ots` is installed). One `PASS`/`FAIL`/`SKIP`
line per check; exit codes `0`/`1`/`2`/`3` exactly as specified. Run with no
arguments for full usage.

```
verify.sh [-f] <attestation.json> <evidence-pack.pdf> <pubkey-file> <ledger-export.jsonl>
```

**Canonicalization assumption (please read):** the chain check (spec §6.4,
TDD §8) recomputes each ledger event's hash by taking `jq -cS` (recursively
sorted keys, compact, no added trailing newline) over the event with its `hash`
field set to `""`, then `sha256sum`-ing the result. TDD §8 permits either JCS
(RFC 8785) or "a fixed-key-order serializer with tests" — `jq -cS` is the latter,
chosen because it is achievable within the verifier's fixed dependency set
(`sh`/`minisign`/`sha256sum`/`jq`, no JCS-compliant tool available). **This must
match whatever the ledger-producing tooling in the private `attestable-ops` repo
(`bin/append`, per RUNBOOK §3) actually implements** — that tooling lives outside
this repo and wasn't available to check against while writing this verifier.
Before the first real pack ships, confirm `bin/append`'s hash computation is
byte-for-byte this same serialization, or `verify.sh`'s chain check will FAIL
against genuinely-untampered ledgers.

### Testing

```bash
dash tests/run_tests.sh
```

Generates a throwaway minisign keypair (`test-fixture-key`, `-W`/no-password) inside
a temp directory for the duration of the run only — nothing test-related is ever
written outside `tests/`, and no key material from these tests is ever committed.
Covers: a clean pass; pin mismatch; both minisign signature failures; a tampered
ledger event (hash mismatch); a broken `prev_hash` link; a ledger-head/attestation
disagreement; a missing input file; zero-args and `-h` help behavior; the online
manifest check (active-in-window and revoked-outside-window, via a stubbed `curl`);
and the anchor check (pass/fail, via a stubbed `ots`).

```bash
shellcheck -s dash -x verify.sh tests/run_tests.sh tests/lib.sh
```

should report nothing.

## ⚠️ HUMAN — cannot be done by an assistant, do these yourself

No tool available in this environment can create Cloudflare resources
(no `wrangler`, no Cloudflare API credentials, and the Cloudflare MCP tools
present here cover Workers/D1/KV/R2/Hyperdrive — not Pages project or DNS
record creation). Every step below is dashboard/CLI work for a human.

### Cloudflare Pages project setup

1. **Dashboard → Workers & Pages → Create → Pages → Connect to Git** → select
   `DisplaceTech/attestable-keys`.
2. Build settings — this is a pure static site, there is no build step:
   - Framework preset: **None**
   - Build command: *(leave empty)*
   - Build output directory: `/`
   - Production branch: `main`
3. **Deploy.** Cloudflare builds and serves from the repo root as-is; `_headers`
   is picked up automatically.
4. **Pages project → Custom domains → Add custom domain → `keys.displace.tech`.**
   If the `displace.tech` zone is on the same Cloudflare account, Pages creates
   and manages the DNS `CNAME` for you — no separate manual DNS step needed. If
   it's on a different account, add the `CNAME` in the `displace.tech` zone
   pointing at the `*.pages.dev` hostname Cloudflare gives you, then add the
   custom domain in step 4 once DNS resolves.
5. Verify: `https://keys.displace.tech/keys.json` loads, and
   `curl -sI https://keys.displace.tech/attestable-2026-a.pub` (once minted)
   shows `cache-control: max-age=31536000, immutable` per `_headers`.

### Deploy triggers

The Git integration above already auto-deploys **every push to `main`** — that's
the normal "commit → live" flow this repo is designed around, and it's what
gives the "single source, cannot diverge" property from spec §8. No hook is
required for that.

A **Deploy Hook** is a separate, optional Cloudflare Pages feature: a unique
webhook URL that triggers a fresh deployment of a given branch *without* a new
commit — useful if you ever need to force a rebuild (e.g. after a Cloudflare-side
config change with no repo change). To create one: **Pages project → Settings →
Builds & deployments → Deploy hooks → Add deploy hook** (name it, pick branch
`main`). It hands you a URL; triggering it is just:
```bash
curl -X POST "<the deploy hook URL Cloudflare gives you>"
```
Not needed for routine key/manifest updates — those go live on push automatically.

### Remaining checklist

- [ ] Cloudflare Pages project created and deploying `main` (above).
- [ ] Custom domain `keys.displace.tech` attached and resolving over HTTPS.
- [ ] Turn on branch protection for `main` on GitHub (no force push — spec §8).
- [ ] Complete the first key commit above; replace every `PENDING-OFFLINE-MINT`
      fingerprint with the real one.
- [ ] Run `ots stamp` at mint time and `ots upgrade` ~24h later on
      `attestable-2026-a.pub.ots`; publish the upgraded proof.
- [ ] Separately, on the `displace.tech` site/repo (not this one): publish
      `/.well-known/security.txt` per spec §9.
