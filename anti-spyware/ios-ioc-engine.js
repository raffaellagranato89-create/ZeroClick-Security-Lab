/*
 * SENTINEL IOC engine — local, consent-based, conservative.
 * This module only examines text explicitly supplied by the user.
 * It does not inspect iOS processes, private memory, installed apps, or the filesystem.
 */

export const ENGINE_VERSION = "0.1.0";

export const DEFAULT_IOC_PACK = Object.freeze({
  schemaVersion: 1,
  packId: "sentinel-empty-baseline",
  source: "No external IOC feed configured",
  publishedAt: null,
  indicators: []
});

const allowedTypes = new Set(["sha256", "domain", "url", "file_path", "process_name", "bundle_id", "package_name"]);

function normalize(type, value) {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  if (type === "sha256") return raw.toLowerCase();
  if (type === "domain") return raw.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (type === "url") {
    try {
      const u = new URL(raw);
      return (u.protocol + "//" + u.host + u.pathname).toLowerCase();
    } catch { return raw.toLowerCase(); }
  }
  return raw.toLowerCase().replace(/\\/g, "/");
}

function validatePack(pack) {
  if (!pack || pack.schemaVersion !== 1 || !Array.isArray(pack.indicators)) {
    throw new TypeError("Pacchetto IOC non valido: schemaVersion 1 e indicators sono obbligatori.");
  }
  for (const item of pack.indicators) {
    if (!item || !allowedTypes.has(item.type) || !String(item.value ?? "").trim() || !String(item.id ?? "").trim() || !String(item.source ?? "").trim()) {
      throw new TypeError("Ogni IOC deve avere id, type, value e source verificabili.");
    }
  }
}

export function analyzeTextArtifact(text, pack = DEFAULT_IOC_PACK) {
  validatePack(pack);
  const content = String(text ?? "");
  const lower = content.toLowerCase();
  const matches = [];

  for (const item of pack.indicators) {
    const needle = normalize(item.type, item.value);
    if (!needle) continue;
    const haystack = item.type === "sha256" ? lower : lower;
    if (haystack.includes(needle)) {
      matches.push({
        id: item.id,
        type: item.type,
        value: item.value,
        source: item.source,
        reference: item.reference ?? null,
        publishedAt: item.publishedAt ?? pack.publishedAt ?? null,
        interpretation: "Corrispondenza testuale con un IOC: richiede verifica del contesto e della provenienza."
      });
    }
  }

  return {
    engineVersion: ENGINE_VERSION,
    packId: pack.packId ?? "custom",
    packSource: pack.source ?? "Fonte non specificata",
    analyzedCharacters: content.length,
    status: matches.length ? "indicator_match" : "no_known_match",
    matches,
    limitations: [
      "Sono stati analizzati soltanto i dati forniti esplicitamente.",
      "Nessuna corrispondenza non esclude spyware o indicatori non inclusi nel pacchetto.",
      "Una corrispondenza non dimostra da sola un'infezione: verificare contesto, data e fonte."
    ]
  };
}

export function summarizeChecks(checks = []) {
  const valid = Array.isArray(checks) ? checks : [];
  const matches = valid.filter(x => x?.status === "indicator_match").length;
  const review = valid.filter(x => x?.status === "review_required").length;
  const notTested = valid.filter(x => x?.status === "not_tested").length;
  return {
    indicatorMatches: matches,
    reviewRequired: review,
    notTested,
    overallStatus: matches ? "indicator_match" : review || notTested ? "review_required" : "no_known_match",
    statement: matches
      ? "Sono presenti corrispondenze con indicatori: è necessaria un'analisi forense."
      : "Nessuna corrispondenza nota nei controlli eseguiti; non è una certificazione di assenza di spyware."
  };
}
