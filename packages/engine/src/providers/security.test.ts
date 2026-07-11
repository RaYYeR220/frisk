import { describe, expect, it } from "vitest";
import { mapSecurityScan, type SecurityScan } from "./security";

const ADDR = "0x1111111111111111111111111111111111111111";

describe("mapSecurityScan", () => {
  it("marks a clean LOW-risk token with an informational finding only", () => {
    const f = mapSecurityScan({ riskLevel: "LOW", isHoneypot: false }, ADDR);
    expect(f).toHaveLength(1);
    expect(f[0]!.code).toBe("SECURITY_SCAN_CLEAN");
    expect(f[0]!.severity).toBe("none");
  });

  it("flags a honeypot as critical", () => {
    const f = mapSecurityScan({ riskLevel: "HIGH", isHoneypot: true }, ADDR);
    expect(f.some((x) => x.code === "HONEYPOT_HEURISTIC" && x.severity === "critical")).toBe(true);
    // no informational clean finding when real risks fire
    expect(f.some((x) => x.code === "SECURITY_SCAN_CLEAN")).toBe(false);
  });

  it("flags mint authority and fund linkage", () => {
    const scan: SecurityScan = { isMintable: true, isFundLinkage: true, isCounterfeit: true };
    const f = mapSecurityScan(scan, ADDR);
    expect(f.some((x) => x.code === "MINT_AUTHORITY")).toBe(true);
    expect(f.filter((x) => x.code === "DENYLIST_HIT")).toHaveLength(2); // fundLinkage + counterfeit
  });

  it("flags punitive taxes (fraction or percent scale)", () => {
    expect(mapSecurityScan({ sellTaxes: "0.30" }, ADDR).some((x) => x.code === "HONEYPOT_HEURISTIC")).toBe(true);
    expect(mapSecurityScan({ buyTaxes: "25" }, ADDR).some((x) => x.code === "HONEYPOT_HEURISTIC")).toBe(true);
    expect(mapSecurityScan({ sellTaxes: "0" }, ADDR).some((x) => x.code === "HONEYPOT_HEURISTIC")).toBe(false);
  });

  it("escalates a HIGH riskLevel even with no specific flag", () => {
    const f = mapSecurityScan({ riskLevel: "HIGH" }, ADDR);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("high");
  });
});
