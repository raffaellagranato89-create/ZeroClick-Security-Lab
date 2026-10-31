/*
 * SENTINEL IOC engine — local, consent-based, conservative.
 * Only examines text explicitly selected by the user.
 * It cannot inspect iOS processes, private memory, installed apps, or files.
 */
export const ENGINE_VERSION = "0.2.0";
export const DEFAULT_IOC_PACK = Object.freeze({
  schemaVersion: 1, packId: "sentinel-empty-baseline",
  source: "No external IOC feed configured", publishedAt: null, indicators: []
});
const allowedTypes = new Set(["sha256","domain","url","file_path","process_name","bundle_id","package_name"]);
const clean = value => String(value ?? "").trim().toLowerCase();
function normalize(type,value) {
  const raw=String(value ?? "").trim();
  if(type==="sha256") return raw.toLowerCase();
  if(type==="domain") return raw.toLowerCase().replace(/^\*\./,"").replace(/\.$/,"");
  if(type==="url") {
    try { const u=new URL(raw); return (u.protocol+"//"+u.host+u.pathname).toLowerCase(); }
    catch { throw new TypeError("IOC URL non valido: "+raw); }
  }
  return raw.toLowerCase().replace(/\\/g,"/");
}
function validatePack(pack) {
  if(!pack || pack.schemaVersion!==1 || !Array.isArray(pack.indicators))
    throw new TypeError("Pacchetto IOC non valido: schemaVersion 1 e indicators sono obbligatori.");
  if(pack.indicators.length>100000) throw new TypeError("Pacchetto IOC troppo grande: massimo 100.000 indicatori.");
  const ids=new Set();
  for(const item of pack.indicators) {
    if(!item || !allowedTypes.has(item.type) || !String(item.value??"").trim() || !String(item.id??"").trim() || !String(item.source??"").trim())
      throw new TypeError("Ogni IOC deve avere id, type, value e source.");
    if(ids.has(item.id)) throw new TypeError("ID IOC duplicato: "+item.id);
    ids.add(item.id);
    const value=normalize(item.type,item.value);
    if(item.type==="sha256" && !/^[a-f0-9]{64}$/.test(value)) throw new TypeError("Hash SHA-256 non valido per IOC "+item.id);
    if(item.type==="domain" && (value.length>253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)))
      throw new TypeError("Dominio non valido per IOC "+item.id);
  }
}
function escapeRegExp(value) { return value.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"); }
function containsIndicator(content,item,needle) {
  if(item.type==="sha256") return new RegExp("(^|[^a-f0-9])"+escapeRegExp(needle)+"($|[^a-f0-9])","i").test(content);
  if(item.type==="domain") return new RegExp("(^|[^a-z0-9.-])"+escapeRegExp(needle)+"($|[^a-z0-9.-])","i").test(content);
  if(item.type==="url") return new RegExp(escapeRegExp(needle)+"(?=$|[?#\\s\\\"'<>])","i").test(content);
  const token=escapeRegExp(needle);
  return new RegExp("(^|[^a-z0-9_./-])"+token+"($|[^a-z0-9_./-])","i").test(content.replace(/\\\\/g,"/"));
}
export function analyzeTextArtifact(text,pack=DEFAULT_IOC_PACK) {
  validatePack(pack);
  const content=String(text??"");
  const matches=[];
  for(const item of pack.indicators) {
    const needle=normalize(item.type,item.value);
    if(needle && containsIndicator(content,item,needle)) matches.push({
      id:item.id,type:item.type,value:item.value,source:item.source,
      reference:item.reference??null,publishedAt:item.publishedAt??pack.publishedAt??null,
      interpretation:"Corrispondenza IOC nel testo: verificare il contesto e la provenienza; non prova un'infezione."
    });
  }
  const status=matches.length?"indicator_match":pack.indicators.length?"no_known_match":"not_tested";
  return {
    engineVersion:ENGINE_VERSION,packId:pack.packId??"custom",packSource:pack.source??"Fonte non specificata",
    indicatorCount:pack.indicators.length,analyzedCharacters:content.length,status,matches,
    limitations:[
      "Sono stati analizzati soltanto i dati forniti esplicitamente.",
      status==="not_tested"?"Il pacchetto IOC è vuoto: nessun confronto è stato eseguito.":"Nessuna corrispondenza non esclude spyware o indicatori non inclusi nel pacchetto.",
      "Una corrispondenza non dimostra da sola un'infezione: verificare contesto, data e fonte."
    ]
  };
}
export function summarizeChecks(checks=[]) {
  const valid=Array.isArray(checks)?checks:[];
  const matches=valid.filter(x=>x?.status==="indicator_match").length;
  const review=valid.filter(x=>x?.status==="review_required").length;
  const notTested=valid.filter(x=>x?.status==="not_tested").length;
  return {
    indicatorMatches:matches,reviewRequired:review,notTested,
    overallStatus:matches?"indicator_match":review||notTested?"review_required":"no_known_match",
    statement:matches?"Sono presenti corrispondenze IOC: è necessaria un'analisi forense.":
      "Nessuna corrispondenza nota nei controlli eseguiti; non è una certificazione di assenza di spyware."
  };
}
