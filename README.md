# Frisk

**A pre-payment safety layer for the agent economy. Frisk it before you trust it.**

![License: MIT](https://img.shields.io/badge/License-MIT-informational)
![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)
![Network](https://img.shields.io/badge/network-X%20Layer-black)
![Tests](https://img.shields.io/badge/tests-116%20passing-success)

Autonomous agents are starting to spend real money — paying per API call, signing
[x402](https://github.com/coinbase/x402) payments, and accepting tasks from other agents on open
marketplaces. The moment an agent can move funds on its own, it becomes a target: a rewritten
recipient, an inflated invoice, a swapped settlement asset, a signature quietly decoupled from the
deal, or a task laced with an instruction to leak its private key.

Frisk is the check an agent runs **before** it pays or signs. Hand Frisk the deal you *think* you
agreed to, plus the x402 challenge you just received, and it runs four independent detectors and
returns a single verdict — **`ALLOW` / `WARN` / `BLOCK`** — backed by a signed, on-chain,
bond-backed attestation. If Frisk is wrong about "safe," its bond can be slashed. That turns a risk
opinion into skin-in-the-game insurance.

Frisk ships as a priced **ASP (Agent Service Provider)** on OKX.AI / X Layer: callable over x402,
exposed as an **MCP tool**, and wrappable as a **drop-in buyer SDK** that frisks every payment
automatically.

---

## Table of contents

- [How it works](#how-it-works)
- [The four detectors](#the-four-detectors)
- [The signed attestation](#the-signed-attestation)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Integration surface](#integration-surface)
- [Configuration](#configuration)
- [Proof](#proof)
- [Limitations & roadmap](#limitations--roadmap)
- [License](#license)

---

## How it works

A buyer-agent negotiates a deal, receives an HTTP `402 Payment Required` challenge, and is about to
sign an EIP-3009 `transferWithAuthorization`. Frisk sits in the gap between *what the buyer meant*
and *what the buyer is about to sign*.

```
   buyer-agent                     resource / seller-agent
       │                                    │
       │ 1. request resource                │
       │───────────────────────────────────▶│
       │                                    │
       │ 2. HTTP 402 + x402 challenge       │
       │◀───────────────────────────────────│
       │                                    │
       │ 3. POST /v1/preflight              │        ┌──────────────────────────────┐
       │   { intent, challenge, payload,    │        │            FRISK             │
       │     target, task }                 │        │  ┌────────────────────────┐  │
       │───────────────────────────────────────────▶│  │ payment · target ·     │  │
       │                                    │        │  │ task · counterparty    │  │
       │                                    │        │  └──────────┬─────────────┘  │
       │                                    │        │   composite scorer          │
       │ 4. FriskVerdict + signed EIP-712   │        │   EIP-712 signer            │
       │◀───────────────────────────────────────────│  └──────────────────────────┘
       │                                    │
       │   ALLOW ─▶ sign & pay              │
       │   WARN  ─▶ pay only on policy      │
       │   BLOCK ─▶ never sign. done.       │
       │                                    │
       │ 5. (optional) anchor attestation on-chain ──▶ FriskRegistry (X Layer)
```

The buyer never signs the drainer. That is the whole product.

---

## The four detectors

Each detector is independent, returns a `0–100` risk score with structured `Finding`s, and reports
`ran: false` (never throws) when it lacks the input it needs. A composite scorer takes the worst
detector score, nudges it up when a second signal fires (defence in depth), and maps it to a
decision: **`< 25` ALLOW · `25–60` WARN · `≥ 61` BLOCK**. Any single **critical** finding forces
`BLOCK` regardless of the number.

| Detector | What it checks | Representative findings |
|---|---|---|
| **payment-integrity** ⭐ | Validates the x402 challenge against the buyer's negotiated intent **and** the EIP-3009 authorization about to be signed. Catches a rewritten `payTo`, an inflated amount, an asset/network swap, a requirement the server never offered, and — the drain vector — a signed authorization decoupled from the presented terms (recovers the signer with viem to prove the signature really binds the buyer to *this* deal). Pure, no network. | `PAYTO_MISMATCH`, `AMOUNT_INFLATED`, `ASSET_SWAP`, `NETWORK_MISMATCH`, `UNOFFERED_REQUIREMENT`, `AUTH_DECOUPLED_FROM_INTENT` |
| **target-risk** | Screens the contract/token/payee: EOA vs contract, bundled + pluggable scam/drainer denylist, ERC-20 red flags (live owner/mint authority, `paused()` honeypot, punitive fee-on-transfer), and deploy freshness. Orchestrates over **OKX OnchainOS** token-security scanning (honeypot / mint / tax / fund-linkage / counterfeit) and folds its verdict in; degrades to built-in heuristics if the scanner is unavailable. | `DENYLIST_HIT`, `HONEYPOT_HEURISTIC`, `MINT_AUTHORITY`, `UNVERIFIED_CONTRACT`, `FRESH_DEPLOY` |
| **task-injection** ⭐ | Screens task text an agent is asked to execute. A deterministic heuristic floor (jailbreak / "ignore previous instructions", system-prompt override, seed/private-key exfiltration, unlimited-approval & `setApprovalForAll` coercion, tool/shell abuse, hidden zero-width & Unicode-tag characters, encoded blobs) runs with **no API key**. An **optional LLM classifier** can only *add* signal — it is fail-open and never suppresses a heuristic finding. | `KEY_EXFIL_ATTEMPT`, `PROMPT_INJECTION`, `HIDDEN_INSTRUCTION`, `OBFUSCATION` |
| **counterparty-reputation** | Reads the seller agent's on-marketplace reputation via its ERC-8004 identity + history (jobs completed, rating, dispute rate, identity age). Fixture-backed for tests/demo; an OnchainOS-backed provider is the production seam. | `UNKNOWN_COUNTERPARTY`, `NEW_IDENTITY`, `LOW_REPUTATION`, `HIGH_DISPUTE_RATE` |

---

## The signed attestation

Every verdict can be sealed into an **EIP-712 attestation** shaped like an
[ERC-8004](https://eips.ethereum.org/) Validation-Registry record. Its struct matches the Solidity
`Verdict` byte-for-byte, so a signature produced by the TypeScript signer verifies on-chain against
the same digest (this parity is covered by a dedicated test).

```
Verdict {
  bytes32 subject;       // the assessed address (padded) or the intent hash
  bytes32 intentHash;    // keccak256 of the canonical deal — binds the verdict to what the buyer meant
  uint8   decision;      // 0 ALLOW · 1 WARN · 2 BLOCK
  uint16  score;         // 0..100
  bytes32 findingsHash;  // commits to exactly the findings reported
  uint64  issuedAt;
  uint64  expiresAt;
  address validator;     // Frisk's signing key
  bytes32 nonce;
}
```

Because the attestation commits to `intentHash` and `findingsHash`, a verdict cannot be replayed
against a different deal or a doctored finding set. Anyone — usually the buyer that received it — can
anchor a signed verdict in **`FriskRegistry`** by calling `recordAttestation`. The registry holds
Frisk's **slashable validator bond** and a dispute path:

- A "safe" (`ALLOW`/`WARN`) attestation can be challenged before it expires by posting a bond
  (`openDispute`). A `BLOCK` is not disputable — Frisk warned, there is nothing to insure.
- An arbiter resolves the dispute (`resolveDispute`); if the validator was wrong, part of its bond
  is **slashed** to the challenger and the attestation is invalidated.
- Bond integrity is enforced structurally: a validator cannot back new attestations while unbonding,
  verdict validity windows are bounded, and the withdrawal cooldown outlasts any live attestation —
  so bond can never leave before a verdict it backs has expired and been made undisputable.

A free `frisk_verify_attestation` / `POST /v1/verify` path checks any presented attestation's
signature and its on-chain status.

---

## Architecture

A pnpm monorepo (TypeScript / Node 20) plus a Foundry contracts package.

| Package | Role |
|---|---|
| **`packages/shared`** | The locked contract every package imports: types, X Layer constants, canonical/deterministic hashing (`intentHash`, `findingsHash`), the EIP-712 attestation typed-data, and the composite scorer. |
| **`packages/engine`** | The four detectors + composite scorer. Produces an *unsigned* `FriskVerdict`. Pure and offline-testable; on-chain reads use viem and degrade gracefully. |
| **`packages/asp`** | The x402-priced HTTP service (`POST /v1/preflight`) and the MCP server. Runs the engine, signs the attestation, and can anchor it on-chain. |
| **`packages/guard`** | A drop-in buyer SDK: `createGuardedFetch` frisks every x402 payment before it is signed. |
| **`contracts`** | Foundry — `FriskRegistry`: EIP-712 attestation anchoring + validator bond + dispute/slash. Solidity 0.8.28, OpenZeppelin 5. |

```
                       ┌─────────────────────────────────────────────┐
                       │                @frisk/shared                 │
                       │  types · constants · hashing · EIP-712 · scorer│
                       └───────────────┬───────────────┬─────────────┘
                                       │               │
                         ┌─────────────▼──┐        ┌───▼───────────┐
                         │  @frisk/engine │        │  @frisk/guard │
                         │  4 detectors   │        │  guarded fetch│
                         └───────┬────────┘        └───────────────┘
                                 │
                         ┌───────▼────────┐        ┌───────────────────────┐
                         │   @frisk/asp   │──sign──▶│  contracts/           │
                         │  x402 · MCP    │ anchor  │  FriskRegistry (X Layer)│
                         └────────────────┘        └───────────────────────┘
```

**Stack:** TypeScript, viem, `@okxweb3/x402-express` + `x402-fetch` + `x402-evm` + `x402-core`,
`@modelcontextprotocol/sdk`, Express 5, Zod; Solidity 0.8.28 + Foundry + OpenZeppelin; X Layer
(mainnet `196`, testnet `1952`), USDT0 settlement.

---

## Quickstart

**Prerequisites:** Node ≥ 20, [pnpm](https://pnpm.io) 9, and (for contracts)
[Foundry](https://book.getfoundry.sh). Clone with submodules so OpenZeppelin is present:

```bash
git clone --recurse-submodules <repo-url> frisk && cd frisk
pnpm install
```

### 1. Offline 60-second demo (no keys, no network)

```bash
pnpm --filter @frisk/asp exec tsx scripts/demo.ts
```

Runs the real engine on two deals: a **malicious** one (rewritten `payTo` + 10× amount + a
key-exfiltration task) → `BLOCK` with a per-detector breakdown and a signed attestation whose
signature is verified live; and a **clean** one (everything matches) → `ALLOW`.

### 2. Run the ASP

```bash
cp packages/asp/.env.example packages/asp/.env   # then fill it in — see Configuration
pnpm --filter @frisk/asp dev
```

Serves `POST /v1/preflight` (x402-priced), `POST /v1/verify` (free), `GET /health`, and
`GET /.well-known/agent.json`. Set `FRISK_DEV_BYPASS=1` to serve the paid route for free during
local testing.

### 3. Contracts

```bash
forge test --root contracts
```

### 4. Guard a buyer-agent — six lines

```ts
import { createGuardedFetch } from "@frisk/guard";
import { wrapFetchWithPaymentFromConfig } from "@okxweb3/x402-fetch";

const guardedFetch = createGuardedFetch({
  friskUrl: "https://frisk-930639894082.europe-west1.run.app",
  pay: wrapFetchWithPaymentFromConfig(/* your x402 EVM signer config */),
});

// On a 402, Frisk checks the challenge against your deal and throws FriskBlockedError
// instead of paying a drainer. Non-402 responses pass straight through.
const res = await guardedFetch("https://seller.example/report", {}, {
  expectedPayTo: "0x1111111111111111111111111111111111111111",
  expectedAmount: "0.5",
  expectedAsset: "USDT0",
});
```

### 5. Run Frisk as an MCP server

```bash
pnpm --filter @frisk/asp mcp
```

Exposes two tools over stdio to any MCP client:

- **`frisk_preflight`** — screen a payment/task/counterparty before paying or signing; returns the
  signed verdict.
- **`frisk_verify_attestation`** — verify an EIP-712 attestation another agent handed you.

---

## Integration surface

**HTTP (the ASP)**

| Route | Cost | Purpose |
|---|---|---|
| `POST /v1/preflight` | x402-priced (`$0.05` USDT0, configurable) | Run all applicable detectors; return a signed `FriskVerdict`. Body is a `FriskRequest`. |
| `POST /v1/verify` | free | Verify a presented attestation's signature and on-chain validity. |
| `GET /.well-known/agent.json` | free | Agent card: services, network, signer, registry, x402 info. |
| `GET /health` | free | Liveness. |

**MCP:** `frisk_preflight`, `frisk_verify_attestation` — the same engine and signing path as HTTP.

**SDK:** `@frisk/guard` `createGuardedFetch` — a payment-capable `fetch` that frisks on every 402.

---

## Configuration

The ASP is configured through environment variables (`packages/asp/.env.example`). Everything runs
without secrets in dev-bypass mode; production values are only needed for the paid route and signed
attestations.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `FRISK_NETWORK` | no | `testnet` | `mainnet` (X Layer 196) or `testnet` (X Layer 1952). |
| `FRISK_SIGNER_PK` | for signed verdicts | — | Frisk's attestation signing key (32-byte hex). Without it, verdicts return unsigned. |
| `FRISK_PAYTO` | for the paid route | signer address | Address that receives x402 payments for `/v1/preflight`. |
| `FRISK_REGISTRY_ADDR` | for anchoring | — | Deployed `FriskRegistry` (EIP-712 `verifyingContract` + on-chain anchor target). |
| `XLAYER_RPC` | no | public X Layer RPC | Custom RPC endpoint. |
| `ANTHROPIC_API_KEY` | no | — | Enables the optional LLM layer of the task-injection detector. Heuristics run without it. |
| `OKX_API_KEY` / `OKX_SECRET_KEY` / `OKX_PASSPHRASE` | for the live paid route | — | OKX facilitator credentials that settle x402 payments. Not needed with `FRISK_DEV_BYPASS=1`. |
| `FRISK_DEV_BYPASS` | no | off | `1` serves `/v1/preflight` for free (local demos / CI). |
| `FRISK_PRICE` | no | `$0.05` | Per-call price for the paid route. |
| `PORT` | no | `8080` | HTTP port. |

The real `.env` is gitignored; only `.env.example` is committed.

---

## Proof

- **Live ASP** (public HTTPS, speaks x402):
  <https://frisk-930639894082.europe-west1.run.app>
- **`FriskRegistry`** on X Layer testnet (chain `1952`): `0xB3E1F28dB5d7eCEE109B0757805791413247a1C9`
  → [view on OKLink](https://www.oklink.com/xlayer-test/address/0xB3E1F28dB5d7eCEE109B0757805791413247a1C9)
- **On-chain attestation anchored** (`recordAttestation` tx):
  [`0x2409a75a…afd4d6b5`](https://www.oklink.com/xlayer-test/tx/0x2409a75a91eb4701a9161f7d2cc9bdd88d0ac76922ca6d794de71362afd4d6b5)
- **Full buyer→ASP x402 paid call** with real settlement (tx):
  [`0xc62afd6e…81f286dc`](https://www.oklink.com/xlayer-test/tx/0xc62afd6eb777e50a8443841d7666820cecdb7ea00109fc9c137e825781f286dc)
- **Tests: 116 passing** — engine `82`, contracts `26`, ASP `4`, guard `4` — including adversarial
  payment-integrity vectors (payTo-rewrite, amount-inflate, asset-swap, unoffered-requirement,
  decoupled-auth), a prompt-injection corpus, and dispute/slash/bond-accounting invariants. A parity
  test confirms the TypeScript signer and the Solidity verifier produce the same EIP-712 digest.

Reproduce:

```bash
pnpm install
pnpm test                    # engine + asp + guard
forge test --root contracts  # FriskRegistry
```

---

## Limitations & roadmap

Frisk is early and deliberately honest about its edges:

- **Testnet-first.** The registry and proof transactions live on X Layer testnet. Mainnet promotion
  is a config flip (`FRISK_NETWORK=mainnet`), pending a mainnet bond deposit.
- **Arbiter-based disputes.** Slashing is resolved by a single trusted arbiter today. A full
  evaluator-network dispute resolution (multiple independent evaluators, staked, adjudicating
  disputes) is roadmap; the contract interface is kept clean for that upgrade.
- **Denylist & reputation are pluggable, not exhaustive.** The bundled scam denylist is a small seed
  and demo fixture; production deployments inject a live threat-intel feed and an OnchainOS-backed
  reputation provider. The interfaces exist; the feeds are operator-supplied.
- **Detectors reduce risk, they don't eliminate it.** Best-effort on-chain reads degrade to notes on
  RPC errors, and the optional LLM layer is fail-open. A `WARN` is advice, not a guarantee; only a
  `BLOCK` (or any critical finding) is a hard stop.

Roadmap: mainnet promotion, evaluator-network disputes, richer on-chain simulation for the
target detector, and first-class denylist/reputation feed adapters.

---

## License

[MIT](./LICENSE) © Frisk
