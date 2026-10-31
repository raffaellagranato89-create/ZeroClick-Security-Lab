import { analyzeTextArtifact, DEFAULT_IOC_PACK, ENGINE_VERSION } from "./anti-spyware/ios-ioc-engine.js";

const sha = "a".repeat(64);
const pack = indicators => ({
  schemaVersion: 1,
  packId: "automated-test-pack",
  source: "SENTINEL automated tests (synthetic indicators)",
  publishedAt: "2026-01-01",
  indicators
});
const indicator = (id, type, value) => ({ id, type, value, source: "synthetic-test" });

const tests = [
  ["engine version is present", () => typeof ENGINE_VERSION === "string" && ENGINE_VERSION.length > 0],
  ["empty default pack is explicitly not tested", () => analyzeTextArtifact("ordinary text", DEFAULT_IOC_PACK).status === "not_tested"],
  ["SHA-256 exact match is detected", () => analyzeTextArtifact("hash=" + sha, pack([indicator("h1", "sha256", sha)])).matches.length === 1],
  ["SHA-256 partial match is rejected", () => analyzeTextArtifact("a".repeat(63), pack([indicator("h1", "sha256", sha)])).matches.length === 0],
  ["domain match is case-insensitive", () => analyzeTextArtifact("Connect to BAD.EXAMPLE now", pack([indicator("d1", "domain", "bad.example")])).matches.length === 1],
  ["domain substring inside a larger hostname is rejected", () => analyzeTextArtifact("notbad.example.evil", pack([indicator("d1", "domain", "bad.example")])).matches.length === 0],
  ["URL match ignores query and fragment in IOC normalization", () => analyzeTextArtifact("Visit https://bad.example/path?token=abc", pack([indicator("u1", "url", "https://bad.example/path")])).matches.length === 1],
  ["unmatched indicator returns no_known_match", () => analyzeTextArtifact("ordinary text", pack([indicator("d1", "domain", "bad.example")])).status === "no_known_match"],
  ["duplicate IOC IDs are rejected", () => { try { analyzeTextArtifact("x", pack([indicator("same", "domain", "a.example"), indicator("same", "domain", "b.example")])); return false; } catch { return true; } }],
  ["invalid SHA-256 IOC is rejected", () => { try { analyzeTextArtifact("x", pack([indicator("h1", "sha256", "not-a-hash")])); return false; } catch { return true; } }],
  ["unsupported IOC type is rejected", () => { try { analyzeTextArtifact("x", pack([indicator("x1", "email", "a@example.com")])); return false; } catch { return true; } }],
  ["missing IOC source is rejected", () => { try { analyzeTextArtifact("x", pack([{id:"d1",type:"domain",value:"bad.example"}])); return false; } catch { return true; } }],
  ["invalid pack schema is rejected", () => { try { analyzeTextArtifact("x", {schemaVersion:2,indicators:[]}); return false; } catch { return true; } }],
  ["match output includes cautionary interpretation", () => analyzeTextArtifact("bad.example", pack([indicator("d1", "domain", "bad.example")])).matches[0]?.interpretation.includes("non prova") === true]
];

export function runSecurityTests() {
  return tests.map(([name, test]) => {
    try { return { name, passed: test() === true }; }
    catch (error) { return { name, passed: false, error: String(error?.message || error) }; }
  });
}
