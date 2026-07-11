/**
 * taskInjection — screen the task text an agent is being asked to execute.
 *
 * Layer (a): a strong DETERMINISTIC heuristic that runs with no API key — jailbreak / "ignore
 * previous instructions", system-prompt override, seed/private-key/mnemonic exfiltration,
 * unlimited-approval & setApprovalForAll coercion, base64/hex blobs, hidden/zero-width & Unicode-
 * tag characters, and tool-abuse. This is the guaranteed floor.
 *
 * Layer (b): an OPTIONAL LLM classifier (`ctx.classifier`, e.g. AnthropicClassifier) that can only
 * ADD signal. It is fail-open: an error or absence never removes a heuristic finding.
 */

import {
  type Detector,
  type DetectorContext,
  type Finding,
  type FriskRequest,
  type Severity,
  type TaskClassifier,
  type TaskClassifierResult,
} from "@frisk/shared";
import { buildResult, finding, skipped } from "../util";

const D = "task" as const;

export interface HeuristicMatch {
  code: "PROMPT_INJECTION" | "KEY_EXFIL_ATTEMPT" | "HIDDEN_INSTRUCTION" | "OBFUSCATION";
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
}

// ---- lexicons ----
const STRONG_EXFIL = "export|send|transmit|upload|paste|dump|leak|disclose|forward|reply with|e-?mail|dm|hand over|copy|post";
const WEAK_EXFIL = "reveal|show|give|provide|tell|share|print|output|write|type|return|read out|say";
const SECRET_NOUN =
  "private\\s*keys?|priv\\s*keys?|secret\\s*keys?|seed\\s*phrases?|seed\\s*words?|mnemonics?|recovery\\s*phrases?|recovery\\s*seed|keystore|wallet\\s*password|master\\s*keys?|api\\s*keys?|access\\s*tokens?|bearer\\s*tokens?|passwords?";
const POSSESS = "your|the|my|users?'?s?|its|his|her|this\\s+wallet'?s?";

const RX = {
  ignore:
    /\b(ignore|disregard|forget|override|bypass|skip)\b[\s\S]{0,30}\b(all|any|the|your|these|previous|prior|earlier|above|preceding|system|initial)\b[\s\S]{0,30}\b(instructions?|prompts?|messages?|rules?|guardrails?|guidelines?|context|directives?)\b/i,
  persona:
    /\b(you\s+are\s+now|from\s+now\s+on|pretend\s+to\s+be|act\s+as|behave\s+as|roleplay\s+as|enable|activate)\b[\s\S]{0,25}\b(dan|do\s+anything\s+now|developer\s+mode|jailbreak|unrestricted|no\s+restrictions|god\s+mode|admin\s+mode|sudo\s+mode)\b/i,
  revealPrompt:
    /\b(reveal|show|print|repeat|leak|output|expose|disclose|reflect)\b[\s\S]{0,25}\b(your\s+|the\s+|hidden\s+|initial\s+)?(system\s*prompt|system\s+message|initial\s+instructions?|hidden\s+instructions?|prior\s+instructions?)\b/i,
  newInstructions: /\b(new|updated|revised|real|actual)\s+(instructions?|rules?|task|directive)\s*[:：]/i,
  setApprovalForAll: /set\s*approval\s*for\s*all|setapprovalforall\s*\(/i,
  unlimitedApproval:
    /\b(approve|grant|allow|set|authorize|increase)\b[\s\S]{0,30}\b(unlimited|max(imum)?|infinite|unbounded|type\(uint256\)\.max|0x[fF]{16,})\b[\s\S]{0,20}\b(approval|allowance|amount|spend|spender)?/i,
  increaseAllowance: /increaseallowance\s*\(|type\(uint256\)\.max|0x[fF]{40,}/i,
  toolAbuse:
    /\b(use|call|invoke|execute|run|trigger)\b[\s\S]{0,25}\b(your\s+)?(tools?|functions?|the\s+transfer|the\s+send|sendtransaction|transfer\s+function|wallet\s+api|signer)\b/i,
  shellAbuse: /\b(curl|wget)\b[\s\S]{0,60}https?:\/\/|\brun\s+the\s+following\s+(command|code|script|shell)\b|\bexfiltrat/i,
  base64: /(?:[A-Za-z0-9+/]{48,}={0,2})/,
  hexBlob: /(?:0x)?[0-9a-fA-F]{128,}/,
} as const;

function snippet(text: string, match: RegExpMatchArray | null, fallback: string): string {
  const s = match?.[0] ?? fallback;
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
}

/** Detect zero-width, bidi-control and Unicode-tag (hidden-prompt) characters. */
function hiddenUnicode(text: string): { found: boolean; codepoints: string[] } {
  const cps: string[] = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    const hidden =
      (cp >= 0x200b && cp <= 0x200f) || // zero-width + directional marks
      (cp >= 0x202a && cp <= 0x202e) || // bidi overrides
      (cp >= 0x2060 && cp <= 0x2064) || // word-joiner / invisible ops
      cp === 0xfeff || // BOM / zero-width no-break
      cp === 0x00ad || // soft hyphen
      (cp >= 0xe0000 && cp <= 0xe007f); // Unicode tag block (steganographic injection)
    if (hidden) cps.push(`U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
  }
  return { found: cps.length > 0, codepoints: [...new Set(cps)] };
}

function keyExfil(text: string): RegExpMatchArray | null {
  const strongFwd = new RegExp(`(${STRONG_EXFIL})[\\s\\S]{0,45}(${SECRET_NOUN})`, "i");
  const strongRev = new RegExp(`(${SECRET_NOUN})[\\s\\S]{0,30}(${STRONG_EXFIL})`, "i");
  const weakPoss = new RegExp(`(${WEAK_EXFIL})[\\s\\S]{0,25}(${POSSESS})\\s*(${SECRET_NOUN})`, "i");
  return text.match(strongFwd) ?? text.match(weakPoss) ?? text.match(strongRev);
}

/** The deterministic heuristic scan — returns every matched signal (deduped by code). */
export function scanText(text: string): HeuristicMatch[] {
  const matches: HeuristicMatch[] = [];
  const push = (m: HeuristicMatch) => {
    if (!matches.some((x) => x.code === m.code && x.category === m.category)) matches.push(m);
  };

  // key exfiltration (critical)
  const kx = keyExfil(text);
  if (kx) {
    push({
      code: "KEY_EXFIL_ATTEMPT",
      category: "key_exfil",
      severity: "critical",
      title: "Secret/key exfiltration attempt",
      description:
        "The task tries to make the agent reveal or transmit a private key, seed phrase, mnemonic or other secret.",
      evidence: snippet(text, kx, "secret exfiltration"),
    });
  }

  // jailbreak / instruction override
  for (const [cat, re] of [
    ["instruction_override", RX.ignore],
    ["persona_jailbreak", RX.persona],
    ["system_prompt_leak", RX.revealPrompt],
    ["injected_instructions", RX.newInstructions],
  ] as const) {
    const m = text.match(re);
    if (m) {
      push({
        code: "PROMPT_INJECTION",
        category: cat,
        severity: "high",
        title: "Prompt-injection / jailbreak language",
        description: `Detected ${cat.replace(/_/g, " ")} pattern attempting to hijack the agent's instructions.`,
        evidence: snippet(text, m, cat),
      });
    }
  }

  // wallet-drain coercion
  for (const re of [RX.setApprovalForAll, RX.unlimitedApproval, RX.increaseAllowance]) {
    const m = text.match(re);
    if (m) {
      push({
        code: "PROMPT_INJECTION",
        category: "approval_abuse",
        severity: "high",
        title: "Unlimited-approval / drain coercion",
        description:
          "The task coerces the agent into granting an unlimited token approval or setApprovalForAll — the standard wallet-drain primitive.",
        evidence: snippet(text, m, "approval abuse"),
      });
      break;
    }
  }

  // tool / shell abuse
  for (const re of [RX.toolAbuse, RX.shellAbuse]) {
    const m = text.match(re);
    if (m) {
      push({
        code: "PROMPT_INJECTION",
        category: "tool_abuse",
        severity: "high",
        title: "Tool/command abuse",
        description: "The task tries to drive the agent's tools, signer or shell toward an attacker-chosen action.",
        evidence: snippet(text, m, "tool abuse"),
      });
      break;
    }
  }

  // hidden unicode
  const hu = hiddenUnicode(text);
  if (hu.found) {
    push({
      code: "HIDDEN_INSTRUCTION",
      category: "hidden_unicode",
      severity: "high",
      title: "Hidden / zero-width characters",
      description:
        "The task contains zero-width, bidi-override or Unicode-tag characters that can smuggle instructions past a human reviewer.",
      evidence: hu.codepoints.join(" "),
    });
  }

  // obfuscated blobs
  const b64 = text.match(RX.base64);
  const hex = text.match(RX.hexBlob);
  if (b64 || hex) {
    push({
      code: "OBFUSCATION",
      category: "encoded_blob",
      severity: "medium",
      title: "Encoded/obfuscated payload",
      description:
        "The task embeds a long base64 or hex blob — a common way to hide a second-stage instruction or calldata from review.",
      evidence: snippet(text, b64 ?? hex, "encoded blob"),
    });
  }

  return matches;
}

function confidenceFromSeverity(sev: Severity): number {
  return sev === "critical" ? 0.97 : sev === "high" ? 0.85 : sev === "medium" ? 0.55 : 0.2;
}

/** HeuristicTaskClassifier: the deterministic layer exposed as a TaskClassifier. */
export class HeuristicTaskClassifier implements TaskClassifier {
  async classify(text: string): Promise<TaskClassifierResult> {
    const matches = scanText(text);
    if (matches.length === 0) {
      return { injection: false, confidence: 0, categories: [], rationale: "no heuristic signal" };
    }
    const worst = matches.reduce<Severity>(
      (acc, m) =>
        ["none", "low", "medium", "high", "critical"].indexOf(m.severity) >
        ["none", "low", "medium", "high", "critical"].indexOf(acc)
          ? m.severity
          : acc,
      "none",
    );
    return {
      injection: true,
      confidence: confidenceFromSeverity(worst),
      categories: [...new Set(matches.map((m) => m.category))],
      rationale: matches.map((m) => m.title).join("; "),
    };
  }
}

export function createTaskDetector(options: { classifier?: TaskClassifier } = {}): Detector {
  return {
    name: D,
    async run(req: FriskRequest, ctx: DetectorContext) {
      const text = req.task?.text;
      if (typeof text !== "string" || text.trim().length === 0) {
        return skipped(D, "no task text to screen");
      }

      // Layer (a): deterministic heuristic — the guaranteed floor.
      const heur = scanText(text);
      const findings: Finding[] = heur.map((m) =>
        finding(D, m.code, m.severity, m.title, m.description, {
          category: m.category,
          evidence: m.evidence,
          layer: "heuristic",
        }),
      );

      // Layer (b): optional LLM — additive only, fail-open.
      const classifier = options.classifier ?? ctx.classifier;
      let note: string | undefined;
      if (classifier) {
        try {
          const llm = await classifier.classify(text);
          if (llm.injection && llm.confidence >= 0.5) {
            const known = new Set(findings.map((f) => f.evidence?.category as string | undefined));
            const newCats = (llm.categories ?? []).filter((c) => !known.has(c));
            if (findings.length === 0 || newCats.length > 0) {
              const sev: Severity =
                llm.categories?.includes("key_exfil")
                  ? "critical"
                  : llm.confidence >= 0.8
                    ? "high"
                    : "medium";
              findings.push(
                finding(
                  D,
                  llm.categories?.includes("key_exfil") ? "KEY_EXFIL_ATTEMPT" : "PROMPT_INJECTION",
                  sev,
                  "LLM-flagged task injection",
                  llm.rationale ?? "The LLM classifier flagged this task as an injection attempt.",
                  {
                    category: newCats.join(",") || "llm",
                    confidence: llm.confidence,
                    categories: llm.categories,
                    layer: "llm",
                  },
                ),
              );
            }
          }
          note = `llm layer ran (injection=${llm.injection}, confidence=${llm.confidence})`;
        } catch (err) {
          note = `llm layer skipped: ${(err as Error)?.message ?? "error"}`;
        }
      } else {
        note = "heuristic-only (no LLM classifier wired)";
      }

      return buildResult(D, findings, { note });
    },
  };
}
