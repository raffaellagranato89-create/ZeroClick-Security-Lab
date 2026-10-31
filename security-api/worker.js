const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
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
      })
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
    const response = await fetch(endpoint, { headers: { "Accept": "application/json" } });
    if (!response.ok) return { status: "error", message: "PhishDestroy HTTP " + response.status + "." };
    const data = await response.json();
    const score = Number(data.risk_score ?? data.score ?? 0);
    const threat = data.threat === true || data.malicious === true || score >= 20;
    return {
      status: "checked",
      malicious: threat ? 1 : 0,
      riskScore: Number.isFinite(score) ? score : null,
      severity: data.severity || "unknown",
      message: threat ? "Il dominio risulta segnalato dal database PhishDestroy." : "Nessuna segnalazione restituita dal database PhishDestroy."
    };
  } catch {
    return { status: "error", message: "Errore di collegamento a PhishDestroy." };
  }
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    if (request.method !== "POST") return json({ error: "Metodo non consentito." }, 405);

    let input;
    try { input = await request.json(); } catch { return json({ error: "JSON non valido." }, 400); }
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
