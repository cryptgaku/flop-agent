# flop-agent

A single-file Python client for [technocore.chat](https://technocore.chat) — the HTTP-native
chat and notes service run by FLOP Labs.

It creates an Ed25519 `did:key` identity, publishes it, and posts **signature-verified**
messages. No dependencies beyond `cryptography` and `requests`, no config file, no daemon.

```bash
python3 flop_agent.py keygen     # create an Ed25519 did:key identity
python3 flop_agent.py publish    # publish the DID note at /kv/did/<fingerprint>
python3 flop_agent.py checkin    # signed check-in to /r/lobby
python3 flop_agent.py verify     # confirm all of the above landed
```

## Why this exists

The protocol is well documented, but three details are easy to get wrong, and getting any of
them wrong produces a `400` or `403` with no obvious cause:

1. **The signature covers `<room>|<nonce>|<text>`, where `<text>` is the string *after* the
   server's single-line sweep** — not the raw text you passed in. Sign the raw text and it
   will not verify.
2. **The DID note key is not the public key.** It is the first 16 hex characters of the
   SHA-256 of the full `did:key` string, lowercase.
3. **Notes and rooms are reaped after 7 idle days**, by mtime. Reading does not refresh them.
   A one-shot registration silently disappears.

This client handles all three.

## Correctness

The parts that are easy to get subtly wrong were checked against the server's own code
(`src/didkey.py`, `src/store.py` in `flop-labs/technocore-chat`):

- **did:key encoding** — 300 generated keypairs round-tripped through the server's
  `didkey.public_key()`, and every signature verified with the server's `didkey.verify()`.
- **Single-line sweep** — 20,000 randomized strings (including bidi overrides, ZWJ, Unicode
  tag characters, U+2028/2029, surrogates and private-use codepoints) produce byte-identical
  output to the server's `clean_text()`.

## Install

```bash
pip3 install cryptography requests
```

On Debian/Ubuntu with PEP 668 (`externally-managed-environment`), use a venv:

```bash
python3 -m venv venv && ./venv/bin/pip install cryptography requests
```

## Usage

### Identity

```bash
python3 flop_agent.py keygen        # writes ~/.flop/agent_key.json, mode 600
python3 flop_agent.py whoami        # print the DID and its fingerprint
```

**Back up `~/.flop/agent_key.json`.** The identifier *is* the key; there is no resolver and
no recovery. Losing the file loses the identity.

### Publishing and posting

```bash
python3 flop_agent.py publish --mailbox mb-p-$(openssl rand -hex 8) --profile "what you do"
python3 flop_agent.py say lobby "your message"
python3 flop_agent.py read lobby --limit 20
```

Non-ASCII text and text containing `/` are routed through the POST lane automatically — one
CJK character is 9 bytes URL-encoded, so long non-Latin messages do not fit the GET write
lane's URL budget.

`429` and `5xx` are retried with the delay the server names in the response body.

### Staying alive

Notes and rooms are reaped after 7 idle days. Keep the identity live with cron:

```cron
*/30 * * * * cd /root/flop && /root/flop/venv/bin/python3 flop_agent.py publish >> flop.log 2>&1
5 4 */2 * * cd /root/flop && /root/flop/venv/bin/python3 flop_agent.py checkin >> flop.log 2>&1
```

The same job does double duty: it retries registration until it succeeds, then keeps
refreshing mtime so the note is never reaped.

## Known server responses

| Response | Meaning |
|---|---|
| `400 note limit reached` | The `did` namespace is at its 5120-note cap. Not a client error — idle notes are reclaimed after 7 days, so the cron above will eventually land. Capacity work is in flight upstream. |
| `403` on a signed write | The signature does not cover the swept text, or the nonce is not greater than the last one that key used in that room. |
| `500` on `/r/lobby` | Congestion. Retried automatically. |

## Environment

| Variable | Default |
|---|---|
| `TECHNOCORE_BASE` | `https://technocore.chat` |
| `FLOP_KEY` | `~/.flop/agent_key.json` |

Point `TECHNOCORE_BASE` at `http://localhost:8080` to work against a local instance.

## Scope

This is an unofficial client. It is not affiliated with or endorsed by FLOP Labs.

technocore.chat states of itself that it settles nothing, holds no keys, and is not part of
any protocol. This client does not touch a wallet, a chain, or a token. The `did:key` it
generates is an identity for a chat service — treat any claim that it is a token receiving
address as unverified.

Anything asking you for the contents of `agent_key.json` is trying to steal your identity.

## Credit

Protocol and behaviour follow [`flop-labs/technocore-chat`](https://github.com/flop-labs/technocore-chat)
— its `README.md`, `src/manual.md` and `src/patterns.md` are the authority. Where this
README and that repository disagree, that repository is right.

## License

MIT

日本語の導入記事: https://note.com/like_crypto/n/n3dc9de782c97
