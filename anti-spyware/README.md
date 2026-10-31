# SENTINEL Anti-Spyware Engine — fase iniziale

Questa cartella introduce il motore di analisi senza dichiarare capacità che iOS/Android non concedono.

## Principi
- Un IOC è attendibile solo se proviene da un feed verificabile, con fonte, data, versione e hash.
- Una corrispondenza esatta con un IOC viene segnalata come **indicatore da approfondire**, non come prova automatica di infezione.
- Un risultato senza corrispondenze significa soltanto "nessun IOC noto trovato nei dati analizzati".
- Nessun caricamento automatico di backup, log o file personali.
- Nessun controllo dei processi o della memoria privata da una PWA.

## Motore JavaScript
`ios-ioc-engine.js` analizza esclusivamente testo/JSON fornito esplicitamente dall'utente e confronta indicatori esatti presenti in un pacchetto IOC locale. Non scarica feed e non inventa firme. Il pacchetto IOC predefinito è vuoto finché non viene aggiunta una fonte verificata.

## iOS
Per analisi più approfondite, l'utente può esportare volontariamente dati diagnostici compatibili. Per casi mirati, MVT (Mobile Verification Toolkit) è uno strumento forense esterno da eseguire in un ambiente appropriato; SENTINEL non deve dichiararsi equivalente a MVT.

## Android
La fase nativa Android dovrà richiedere autorizzazioni esplicite e usare API ufficiali per inventario app e controlli consentiti. Non promettere scansione completa di altre app, processi o dati privati. Google Play Protect resta un controllo complementare.

## Stati del report
- `indicator_match`: corrispondenza esatta con IOC documentato.
- `review_required`: elemento sospetto o contesto incompleto.
- `no_known_match`: nessuna corrispondenza nel materiale analizzato.
- `not_tested`: controllo non eseguibile o dati non forniti.
