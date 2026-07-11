import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type {
  DetectorContext,
  FriskRequest,
  PaymentPayload,
  PaymentRequired,
  PaymentRequirements,
} from "@frisk/shared";
import { TOKENS, caip2ToChainId } from "@frisk/shared";
import { createPaymentDetector, decodeEip3009 } from "./payment";

// ---------------------------------------------------------------------------
// Real EIP-3009 signing harness (viem local account). We build a genuine
// TransferWithAuthorization signature, then tamper for each adversarial vector.
// ---------------------------------------------------------------------------
const BUYER_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const buyer = privateKeyToAccount(BUYER_PK);
const IMPOSTOR_PK = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";
const impostor = privateKeyToAccount(IMPOSTOR_PK);
const FRISK_PAYTO = "0x1111111111111111111111111111111111111111" as const;
const ATTACKER = "0x2222222222222222222222222222222222222222" as const;
const USDT0 = TOKENS.USDT0.address;
const USDC = TOKENS.USDC.address;
const NETWORK = "eip155:196";
const NONCE = ("0x" + "ab".repeat(32)) as `0x${string}`;
const NOW = 1_700_000_000;
const VALID_BEFORE = NOW + 3600;

const ctx: DetectorContext = { rpcUrl: "", chainId: 196, now: NOW };

const TWA_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

function requirement(over: Partial<PaymentRequirements> = {}): PaymentRequirements {
  return {
    scheme: "exact",
    network: NETWORK,
    amount: "50000", // 0.05 USDT0 (6dp)
    asset: USDT0,
    payTo: FRISK_PAYTO,
    maxTimeoutSeconds: 300,
    extra: { name: "USDT0", version: "1" },
    ...over,
  };
}

async function signAuthorization(args: {
  accepted: PaymentRequirements;
  from?: `0x${string}`;
  to: `0x${string}`;
  value: string;
  validAfter?: string;
  validBefore?: string;
  nonce?: `0x${string}`;
}) {
  const from = args.from ?? buyer.address;
  const validAfter = args.validAfter ?? "0";
  const validBefore = args.validBefore ?? String(VALID_BEFORE);
  const nonce = args.nonce ?? NONCE;
  const extra = (args.accepted.extra ?? {}) as { name: string; version: string };
  const domain = {
    name: extra.name,
    version: extra.version,
    chainId: caip2ToChainId(args.accepted.network)!,
    verifyingContract: args.accepted.asset as `0x${string}`,
  };
  const signature = await buyer.signTypedData({
    domain,
    types: TWA_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from,
      to: args.to,
      value: BigInt(args.value),
      validAfter: BigInt(validAfter),
      validBefore: BigInt(validBefore),
      nonce,
    },
  });
  return { from, validAfter, validBefore, nonce, signature };
}

async function buildPayload(args: {
  accepted: PaymentRequirements;
  to: `0x${string}`;
  value: string;
  from?: `0x${string}`;
  validAfter?: string;
  validBefore?: string;
  nonce?: `0x${string}`;
  signatureOverride?: `0x${string}`;
}): Promise<PaymentPayload> {
  const sig = await signAuthorization(args);
  return {
    x402Version: 2,
    accepted: args.accepted,
    payload: {
      signature: args.signatureOverride ?? sig.signature,
      authorization: {
        from: sig.from,
        to: args.to,
        value: args.value,
        validAfter: sig.validAfter,
        validBefore: sig.validBefore,
        nonce: sig.nonce,
      },
    },
  };
}

function challenge(accepts: PaymentRequirements[]): PaymentRequired {
  return {
    x402Version: 2,
    resource: { url: "https://seller.example/api/data", description: "data" },
    accepts,
  };
}

function baseIntent(over: Partial<FriskRequest["intent"]> = {}): FriskRequest["intent"] {
  return {
    action: "pay",
    expectedPayTo: FRISK_PAYTO,
    expectedAmount: "0.05",
    expectedAsset: USDT0,
    network: NETWORK,
    ...over,
  };
}

const det = createPaymentDetector();
const codes = (r: Awaited<ReturnType<typeof det.run>>) => r.findings.map((f) => f.code);

// ---------------------------------------------------------------------------

describe("payment detector — plumbing", () => {
  it("skips when no challenge", async () => {
    const res = await det.run({ intent: baseIntent() }, ctx);
    expect(res.ran).toBe(false);
  });

  it("decodeEip3009 supports both wrapped and flat shapes", () => {
    const flat = decodeEip3009({
      from: buyer.address,
      to: FRISK_PAYTO,
      value: "50000",
      validAfter: "0",
      validBefore: "123",
      nonce: NONCE,
      signature: "0xabcd",
    });
    expect(flat?.to).toBe(FRISK_PAYTO);
    const wrapped = decodeEip3009({
      signature: "0xabcd",
      authorization: { from: buyer.address, to: FRISK_PAYTO, value: "1", validAfter: "0", validBefore: "1", nonce: NONCE },
    });
    expect(wrapped?.value).toBe("1");
    expect(decodeEip3009({ nope: true })).toBeUndefined();
  });
});

describe("payment detector — adversarial vectors", () => {
  it("VECTOR 0 — clean pass: coherent challenge + valid signature => ALLOW", async () => {
    const req = requirement();
    const payload = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "50000" });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(res.ran).toBe(true);
    expect(res.decision).toBe("ALLOW");
    expect(res.findings.every((f) => f.severity === "none")).toBe(true);
    expect(codes(res)).toContain("AUTH_VERIFIED");
  });

  it("VECTOR 1 — payTo rewrite => PAYTO_MISMATCH (critical, BLOCK)", async () => {
    const req = requirement({ payTo: ATTACKER });
    const payload = await buildPayload({ accepted: req, to: ATTACKER, value: "50000" });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(res.decision).toBe("BLOCK");
    expect(codes(res)).toContain("PAYTO_MISMATCH");
    expect(res.findings.find((f) => f.code === "PAYTO_MISMATCH")?.severity).toBe("critical");
  });

  it("VECTOR 2 — amount inflation (10x) => AMOUNT_INFLATED (critical, BLOCK)", async () => {
    const req = requirement({ amount: "500000" }); // 0.5 vs expected 0.05
    const payload = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "500000" });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(res.decision).toBe("BLOCK");
    expect(codes(res)).toContain("AMOUNT_INFLATED");
    expect(res.findings.find((f) => f.code === "AMOUNT_INFLATED")?.severity).toBe("critical");
  });

  it("VECTOR 3 — asset swap => ASSET_SWAP (high, BLOCK)", async () => {
    const req = requirement({ asset: USDC });
    const payload = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "50000" });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(res.decision).toBe("BLOCK");
    expect(codes(res)).toContain("ASSET_SWAP");
  });

  it("VECTOR 4 — network mismatch => NETWORK_MISMATCH (high, BLOCK)", async () => {
    const req = requirement({ network: "eip155:1952" });
    const payload = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "50000" });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(res.decision).toBe("BLOCK");
    expect(codes(res)).toContain("NETWORK_MISMATCH");
  });

  it("VECTOR 5 — unoffered requirement => UNOFFERED_REQUIREMENT (critical, BLOCK)", async () => {
    const offered = requirement();
    const notOffered = requirement({ payTo: ATTACKER, amount: "50000" });
    const payload = await buildPayload({ accepted: notOffered, to: ATTACKER, value: "50000" });
    // intent left generic so ONLY the unoffered check drives the verdict
    const res = await det.run(
      { intent: { action: "pay" }, paymentChallenge: challenge([offered]), paymentPayload: payload },
      ctx,
    );
    expect(res.decision).toBe("BLOCK");
    expect(codes(res)).toContain("UNOFFERED_REQUIREMENT");
  });

  it("VECTOR 6a — decoupled auth by recipient: signed 'to' != accepted.payTo => AUTH_DECOUPLED (critical)", async () => {
    // The requirement (and UI) say pay FRISK, but the bytes the buyer signed pay the ATTACKER.
    const req = requirement(); // payTo = FRISK
    const payload = await buildPayload({ accepted: req, to: ATTACKER, value: "50000" });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(res.decision).toBe("BLOCK");
    expect(codes(res)).toContain("AUTH_DECOUPLED_FROM_INTENT");
    expect(res.findings.find((f) => f.code === "AUTH_DECOUPLED_FROM_INTENT")?.severity).toBe("critical");
  });

  it("VECTOR 6b — decoupled auth by value: signed value != accepted.amount => AUTH_DECOUPLED", async () => {
    const req = requirement(); // amount 50000
    const payload = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "999999999" });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(codes(res)).toContain("AUTH_DECOUPLED_FROM_INTENT");
  });

  it("VECTOR 6c — forged signature (signed by impostor, not the buyer) => AUTH_DECOUPLED", async () => {
    const req = requirement();
    // A structurally-perfect authorization (to=FRISK, value=50000) but signed by someone who is
    // NOT `from` — recovery lands on the impostor, so signer != from.
    const forged = await impostor.signTypedData({
      domain: { name: "USDT0", version: "1", chainId: 196, verifyingContract: req.asset as `0x${string}` },
      types: TWA_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: buyer.address,
        to: FRISK_PAYTO,
        value: 50000n,
        validAfter: 0n,
        validBefore: BigInt(VALID_BEFORE),
        nonce: NONCE,
      },
    });
    const tampered = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "50000", signatureOverride: forged });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: tampered }, ctx);
    expect(codes(res)).toContain("AUTH_DECOUPLED_FROM_INTENT");
  });

  it("VECTOR 7 — malformed challenge: dangerous resource URL => MALFORMED_CHALLENGE", async () => {
    const req = requirement();
    const bad: PaymentRequired = {
      x402Version: 2,
      resource: { url: "javascript:alert(document.cookie)" },
      accepts: [req],
    };
    const res = await det.run({ intent: baseIntent(), paymentChallenge: bad }, ctx);
    expect(codes(res)).toContain("MALFORMED_CHALLENGE");
  });

  it("VECTOR 8 — expired authorization window => AUTH_EXPIRED", async () => {
    const req = requirement();
    const payload = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "50000", validBefore: String(NOW - 10) });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(codes(res)).toContain("AUTH_EXPIRED");
  });

  it("VECTOR 9 — all-zero nonce => NONCE_REPLAY_RISK", async () => {
    const req = requirement();
    const zero = ("0x" + "00".repeat(32)) as `0x${string}`;
    const payload = await buildPayload({ accepted: req, to: FRISK_PAYTO, value: "50000", nonce: zero });
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(codes(res)).toContain("NONCE_REPLAY_RISK");
  });

  it("VECTOR 10 — missing token domain: structural pass but signer unverifiable => AUTH_UNVERIFIED_DOMAIN", async () => {
    const req = requirement({ extra: null });
    const payload = await buildPayload({ accepted: requirement(), to: FRISK_PAYTO, value: "50000" });
    // present the extra-less requirement so tokenDomain() cannot be built
    payload.accepted = req;
    const res = await det.run({ intent: baseIntent(), paymentChallenge: challenge([req]), paymentPayload: payload }, ctx);
    expect(codes(res)).toContain("AUTH_UNVERIFIED_DOMAIN");
    // no critical => not a hard block from the crypto layer
    expect(res.findings.some((f) => f.code === "AUTH_DECOUPLED_FROM_INTENT")).toBe(false);
  });
});
