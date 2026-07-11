# @frisk/guard

A drop-in `fetch` that frisks every x402 payment before your agent signs it. It probes the
resource, and on an HTTP 402 it reads the payment challenge, asks a Frisk ASP whether the deal is
safe, and only pays if the verdict is not a `BLOCK`.

```ts
import { createGuardedFetch, FriskBlockedError } from "@frisk/guard";
import { wrapFetchWithPaymentFromConfig } from "@okxweb3/x402-fetch";
import { ExactEvmScheme, toClientEvmSigner } from "@okxweb3/x402-evm";

const pay = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [{ network: "eip155:196", client: new ExactEvmScheme(toClientEvmSigner(wallet)) }],
});

const guardedFetch = createGuardedFetch({ friskUrl: "https://frisk.onchain.dev", pay });

try {
  const res = await guardedFetch("https://seller.agent/report", {}, {
    counterpartyAgentId: "seller-agent-42",
    expectedPayTo: "0x1111…",
    expectedAmount: "0.5",
    expectedAsset: "0x779Ded0c9e1022225f8E0630b35a9b54bE713736", // USDT0
  });
} catch (e) {
  if (e instanceof FriskBlockedError) {
    console.error("Blocked:", e.verdict.summary, e.verdict.findings);
  }
}
```

Non-402 responses pass straight through. On `WARN`, `policy.onWarn` fires (and `policy.blockOnWarn`
turns a warning into a hard stop). You can supply your own `preflight` transport for testing.
