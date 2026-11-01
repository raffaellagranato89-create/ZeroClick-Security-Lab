const cors = {
  "Access-Control-Allow-Origin": "https://raffaellagranato89-create.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Vary": "Origin",
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: cors });
}

async function googleCheck(url, key) {
  if (!key) return { status: "not_configured", message: "Google Safe Browsing non configurato." };
  try {
    const response = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(key), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "sentinel-security", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      }),
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) return { status: "error", message: "Google Safe Browsing HTTP " + response.status + "." };
    const data = await response.json();
    const matches = data.matches || [];
    return { status: "checked", malicious: matches.length, message: matches.length ? "URL segnalato da Google Safe Browsing." : "Nessuna corrispondenza trovata." };
  } catch {
    return { status: "error", message: "Errore di collegamento a Google Safe Browsing." };
  }
}

async function destroyListCheck(domain) {
  try {
    const endpoint = "https://api.destroy.tools/v1/check?domain=" + encodeURIComponent(domain);
    const response = await fetch(endpoint, {
      method: "GET",
      headers: { "Accept": "application/json", "User-Agent": "SENTINEL-SECURITY/1.0", "Cache-Control": "no-cache" },
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) return { status: "error", message: "PhishDestroy HTTP " + response.status + "." };
    const data = await response.json();
    const score = Number(data.risk_score ?? data.score ?? 0);
    const threat = data.threat === true;
    return {
      status: "checked",
      malicious: threat ? 1 : 0,
      riskScore: Number.isFinite(score) ? score : null,
      severity: data.severity || "unknown",
      suspicious: data.suspicious === true,
      flags: Array.isArray(data.flags) ? data.flags : [],
      message: threat ? "Il dominio risulta inserito nella blocklist PhishDestroy." : data.suspicious === true ? "Il dominio non risulta bloccato, ma presenta segnali euristici sospetti." : "Il dominio non risulta nella blocklist interrogata; questo non garantisce che sia sicuro."
    };
  } catch {
    return { status: "error", message: "Errore di collegamento a PhishDestroy." };
  }
}

async function lookupMalwareBazaar(hash, key) {
  const body = new URLSearchParams({ query: "get_info", hash });
  const response = await fetch("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) return { source: "MalwareBazaar", status: "error", message: "Servizio non disponibile (HTTP " + response.status + ")." };
  const data = await response.json();
  if (data.query_status === "ok" && Array.isArray(data.data) && data.data.length) {
    const item = data.data[0];
    return {
      source: "MalwareBazaar", status: "match", knownMalware: true,
      family: item.signature || null, fileName: item.file_name || null,
      fileType: item.file_type || null, firstSeen: item.first_seen || null,
      tags: Array.isArray(item.tags) ? item.tags.slice(0, 20) : []
    };
  }
  if (data.query_status === "no_results" || data.query_status === "hash_not_found") {
    return { source: "MalwareBazaar", status: "no_match", knownMalware: false, message: "Hash non presente nei risultati MalwareBazaar." };
  }
  return { source: "MalwareBazaar", status: "error", message: "Risposta API non interpretabile: " + String(data.query_status || "unknown").slice(0, 80) };
}

async function lookupThreatFox(hash, key) {
  const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Auth-Key": key, "Content-Type": "application/json" },
    body: JSON.stringify({ query: "search_hash", hash }),
    signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) return { source: "ThreatFox", status: "error", message: "Servizio non disponibile (HTTP " + response.status + ")." };
  const data = await response.json();
  if (data.query_status === "ok" && Array.isArray(data.data) && data.data.length) {
    const items = data.data.slice(0, 20).map(item => ({
      malware: item.malware_printable || item.malware || null,
      threatType: item.threat_type || null,
      iocType: item.ioc_type || null,
      firstSeen: item.first_seen || null,
      reference: item.reference || null
    }));
    return { source: "ThreatFox", status: "match", knownMalware: true, indicators: items };
  }
  if (data.query_status === "no_result" || data.query_status === "no_results") {
    return { source: "ThreatFox", status: "no_match", knownMalware: false, message: "Hash non presente nei risultati ThreatFox." };
  }
  return { source: "ThreatFox", status: "error", message: "Risposta API non interpretabile: " + String(data.query_status || "unknown").slice(0, 80) };
}

async function lookupHash(hash, env) {
  if (!/^[a-f0-9]{64}$/i.test(hash)) return json({ error: "È richiesto un hash SHA-256 valido." }, 400);
  if (!env.ABUSECH_AUTH_KEY) return json({
    verdict: "NON CONFIGURATO",
    status: "not_configured",
    message: "La chiave personale abuse.ch non è ancora configurata sul server.",
    checkedAt: new Date().toISOString()
  }, 503);
  const results = await Promise.allSettled([
    lookupMalwareBazaar(hash.toLowerCase(), env.ABUSECH_AUTH_KEY),
    lookupThreatFox(hash.toLowerCase(), env.ABUSECH_AUTH_KEY)
  ]);
  const sources = results.map((result, index) => result.status === "fulfilled"
    ? result.value
    : { source: index === 0 ? "MalwareBazaar" : "ThreatFox", status: "error", message: "Errore di collegamento al servizio." });
  const detected = sources.some(source => source.status === "match");
  const checked = sources.some(source => source.status === "match" || source.status === "no_match");
  return json({
    verdict: detected ? "HASH ASSOCIATO A MINACCE NOTE" : checked ? "NESSUNA CORRISPONDENZA NELLE FONTI INTERROGATE" : "VERIFICA NON DISPONIBILE",
    status: detected ? "match" : checked ? "no_match" : "error",
    hash: hash.toLowerCase(),
    sources,
    checkedAt: new Date().toISOString(),
    caution: "Una corrispondenza è un indicatore da approfondire, non una diagnosi definitiva. Nessuna corrispondenza non dimostra che il file sia sicuro."
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    if (request.headers.get("Origin") && request.headers.get("Origin") !== "https://raffaellagranato89-create.github.io") {
      return json({ error: "Origine non autorizzata." }, 403);
    }
    if (request.method !== "POST") return json({ error: "Metodo non consentito." }, 405);

    let input;
    try { input = await request.json(); } catch { return json({ error: "JSON non valido." }, 400); }

    if (input && input.action === "lookup_hash") {
      if (typeof input.hash !== "string") return json({ error: "Hash mancante." }, 400);
      return lookupHash(input.hash.trim(), env);
    }

    if (!input || typeof input.url !== "string" || input.url.length > 2048) {
      return json({ error: "Indirizzo mancante o troppo lungo." }, 400);
    }
    let parsed;
    try { parsed = new URL(input.url); } catch { return json({ error: "URL non valido." }, 400); }
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
      return json({ error: "Sono ammessi solo URL HTTP/HTTPS senza credenziali incorporate." }, 400);
    }
    const [phishDestroy, googleSafeBrowsing] = await Promise.all([
      destroyListCheck(parsed.hostname.toLowerCase()),
      googleCheck(parsed.href, env.GOOGLE_SAFE_BROWSING_API_KEY)
    ]);
    const detected = (phishDestroy.malicious || 0) > 0 || (googleSafeBrowsing.malicious || 0) > 0;
    const configured = [phishDestroy, googleSafeBrowsing].filter(x => x.status === "checked").length;
    const verdict = detected ? "POSSIBILE MINACCIA RILEVATA" :
      configured === 0 ? "VERIFICA NON DISPONIBILE" :
      "NESSUNA MINACCIA RILEVATA DAI SERVIZI INTERROGATI";
    return json({ verdict, phishDestroy, googleSafeBrowsing, checkedAt: new Date().toISOString() });
  }
};
