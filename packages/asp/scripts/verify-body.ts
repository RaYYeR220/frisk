/**
 * Integration check: the /v1/preflight handler must never 500 on a partial/empty business body
 * (an agent-caller may POST an intent-less body). Runs the server in dev-bypass (no x402 payment
 * layer — that is proven separately) and asserts every body returns HTTP 200 with a verdict.
 *
 *   FRISK_DEV_BYPASS=1 pnpm --filter @frisk/asp exec tsx scripts/verify-body.ts
 */
import { createServer } from "../src/server.js";
import { loadConfig } from "../src/config.js";

const PORT = 8093;
const cfg = loadConfig({ devBypass: true });
const app = createServer(cfg);

const bodies: unknown[] = [
  {},
  { task: { text: "hi" } },
  { intent: { action: "pay" } },
  { intent: { action: "pay", expectedPayTo: "0x1111111111111111111111111111111111111111", expectedAmount: "0.5" } },
];

const server = app.listen(PORT, async () => {
  let ok = true;
  for (const body of bodies) {
    const res = await fetch(`http://localhost:${PORT}/v1/preflight`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const j = (await res.json().catch(() => ({}))) as { decision?: string };
    const pass = res.status === 200 && !!j.decision;
    if (!pass) ok = false;
    console.log(`${pass ? "✓" : "✗"} POST ${JSON.stringify(body)} → HTTP ${res.status} decision=${j.decision ?? "-"}`);
  }
  server.close();
  console.log(ok ? "\nALL OK — handler never 500s on a partial body" : "\nFAILED");
  process.exit(ok ? 0 : 1);
});
