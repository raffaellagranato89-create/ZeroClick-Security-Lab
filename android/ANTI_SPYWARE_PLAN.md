# SENTINEL Android — piano per il motore nativo

La PWA attuale non può inventariare in modo affidabile le altre app Android né leggere i dati privati delle app. Per ottenere controlli reali serve un'app Android nativa (Kotlin).

## Controlli candidati, con consenso
1. Inventario delle app visibili tramite le API e le regole di distribuzione applicabili.
2. Revisione di autorizzazioni dichiarate e permessi speciali concessi, ove accessibili.
3. Stato dei servizi di Accessibilità, app amministratrici del dispositivo e VPN: mostrare solo ciò che le API consentono.
4. Verifica di firme e hash dei pacchetti quando l'app ha accesso legittimo ai file APK.
5. Confronto con IOC documentati e aggiornati, con fonte e data.
6. Report con evidenze, limitazioni e azioni manuali consigliate.

## Limiti
- Android limita la visibilità delle app installate e dei dati di altre app; le regole Google Play restringono anche l'uso di QUERY_ALL_PACKAGES.
- Non tentare bypass, root exploit o raccolta nascosta.
- Non classificare un'app come spyware soltanto perché usa accessibilità, VPN o permessi sensibili.
- Integrare Google Play Protect come controllo complementare, non come sostituto.

La PWA iOS resta separata dall'app Android nativa: condividono formato report e pacchetto IOC, non i privilegi di sistema.
