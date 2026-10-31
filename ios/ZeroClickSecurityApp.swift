
import SwiftUI
import UniformTypeIdentifiers
import CryptoKit

@main
struct ZeroClickSecurityApp: App {
    var body: some Scene {
        WindowGroup {
            MainView()
                .preferredColorScheme(.dark)
        }
    }
}

// MARK: - Navigazione principale

struct MainView: View {
    var body: some View {
        TabView {
            DashboardView()
                .tabItem {
                    Label("Home", systemImage: "shield.lefthalf.filled")
                }

            WhatsAppView()
                .tabItem {
                    Label("WhatsApp", systemImage: "message")
                }

            AnalyzerView()
                .tabItem {
                    Label("Analisi", systemImage: "magnifyingglass")
                }

            iPhoneSecurityView()
                .tabItem {
                    Label("iPhone", systemImage: "iphone")
                }

            FileScannerView()
                .tabItem {
                    Label("File", systemImage: "doc.viewfinder")
                }

            LinkScannerView()
                .tabItem {
                    Label("Link", systemImage: "link")
                }
        }
        .tint(.cyan)
    }
}

// MARK: - Dashboard

struct DashboardView: View {
    @AppStorage("check1") private var check1 = false
    @AppStorage("check2") private var check2 = false
    @AppStorage("check3") private var check3 = false
    @AppStorage("check4") private var check4 = false

    @AppStorage("iosUpdateChecked") private var iosUpdateChecked = false
    @AppStorage("passcodeChecked") private var passcodeChecked = false
    @AppStorage("faceIDChecked") private var faceIDChecked = false
    @AppStorage("findMyChecked") private var findMyChecked = false
    @AppStorage("twoFactorChecked") private var twoFactorChecked = false

    private var completed: Int {
        [
            check1, check2, check3, check4,
            iosUpdateChecked, passcodeChecked,
            faceIDChecked, findMyChecked, twoFactorChecked
        ].filter { $0 }.count
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 22) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 68))
                        .foregroundStyle(.cyan)

                    Text("ZERO-CLICK SECURITY")
                        .font(.title2.bold())

                    Text("Protezione personale iPhone")
                        .foregroundStyle(.secondary)

                    VStack(alignment: .leading, spacing: 14) {
                        Text("Stato dei controlli")
                            .font(.headline)

                        HStack {
                            Text("\(completed) controlli completati")
                            Spacer()
                            Text("su 9")
                                .foregroundStyle(.secondary)
                        }

                        ProgressView(value: Double(completed), total: 9)
                            .tint(.cyan)

                        Text("Completa i controlli nelle sezioni WhatsApp e iPhone.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding()
                    .background(Color.white.opacity(0.07))
                    .clipShape(RoundedRectangle(cornerRadius: 16))

                    VStack(alignment: .leading, spacing: 12) {
                        Label("Controllo WhatsApp", systemImage: "message")
                            .font(.headline)

                        Label("Sicurezza iPhone", systemImage: "iphone")
                            .font(.headline)

                        Label("Analisi messaggi", systemImage: "magnifyingglass")
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color.white.opacity(0.07))
                    .clipShape(RoundedRectangle(cornerRadius: 16))

                    Text("Questa applicazione offre controlli guidati e analisi locali. Non rileva autonomamente tutti gli attacchi zero-click.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding()
                }
                .padding()
            }
            .background(Color(red: 0.035, green: 0.05, blue: 0.09))
            .navigationTitle("Security Lab")
        }
    }
}

// MARK: - Sicurezza WhatsApp

struct WhatsAppView: View {
    @AppStorage("check1") private var check1 = false
    @AppStorage("check2") private var check2 = false
    @AppStorage("check3") private var check3 = false
    @AppStorage("check4") private var check4 = false

    var body: some View {
        NavigationStack {
            List {
                Section("Controlli di sicurezza") {
                    Toggle("Ho verificato i dispositivi collegati", isOn: $check1)

                    Toggle("Ho attivato la verifica in due passaggi", isOn: $check2)

                    Toggle("Non condivido codici SMS o PIN", isOn: $check3)

                    Toggle("Ho aggiornato WhatsApp", isOn: $check4)
                }

                Section("Come verificare") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Dispositivi collegati")
                            .font(.headline)

                        Text("Apri WhatsApp → Impostazioni → Dispositivi collegati. Disconnetti quelli che non riconosci.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Verifica in due passaggi")
                            .font(.headline)

                        Text("Apri WhatsApp → Impostazioni → Account → Verifica in due passaggi.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                Section {
                    Text("Le spunte registrano i controlli dichiarati dall'utente. L'app non può leggere direttamente le sessioni o le impostazioni interne di WhatsApp.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("WhatsApp Security")
        }
    }
}

// MARK: - Analisi messaggi

struct AnalyzerView: View {
    @State private var message = ""
    @State private var result = ""
    @State private var riskColor: Color = .secondary

    private func analyze() {
        let text = message.lowercased()

        let highRisk = [
            "codice sms",
            "mandami il codice",
            "codice di verifica",
            "password",
            "mandami il pin",
            "comunica il pin"
        ]

        let mediumRisk = [
            "clicca qui",
            "conto bloccato",
            "urgente",
            "bonifico",
            "hai vinto",
            "premio",
            "verifica account"
        ]

        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            result = "Inserisci un messaggio da analizzare."
            riskColor = .secondary
        } else if highRisk.contains(where: { text.contains($0) }) {
            result = "RISCHIO ALTO: possibile tentativo di furto di credenziali."
            riskColor = .red
        } else if mediumRisk.contains(where: { text.contains($0) }) {
            result = "RISCHIO MEDIO: verifica attentamente il messaggio e il mittente."
            riskColor = .orange
        } else {
            result = "NESSUN INDICATORE RILEVATO: non significa che il messaggio sia sicuro."
            riskColor = .green
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    Image(systemName: "text.magnifyingglass")
                        .font(.system(size: 48))
                        .foregroundStyle(.cyan)

                    Text("Analisi messaggi")
                        .font(.title2.bold())

                    Text("Incolla un messaggio sospetto per analizzarne il contenuto.")
                        .foregroundStyle(.secondary)

                    TextEditor(text: $message)
                        .frame(height: 190)
                        .padding(8)
                        .scrollContentBackground(.hidden)
                        .background(Color.white.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 12))

                    Button(action: analyze) {
                        Label("Analizza messaggio", systemImage: "magnifyingglass")
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(.cyan)
                            .foregroundStyle(.black)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }

                    if !result.isEmpty {
                        Text(result)
                            .font(.headline)
                            .foregroundStyle(riskColor)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding()
                            .background(Color.white.opacity(0.07))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }

                    Text("L'analisi utilizza indicatori testuali e non garantisce l'identificazione di tutte le truffe.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding()
            }
            .navigationTitle("Message Analyzer")
        }
    }
}

// MARK: - Sicurezza iPhone

struct iPhoneSecurityView: View {
    @AppStorage("iosUpdateChecked") private var iosUpdateChecked = false
    @AppStorage("passcodeChecked") private var passcodeChecked = false
    @AppStorage("faceIDChecked") private var faceIDChecked = false
    @AppStorage("findMyChecked") private var findMyChecked = false
    @AppStorage("twoFactorChecked") private var twoFactorChecked = false

    private var completed: Int {
        [
            iosUpdateChecked,
            passcodeChecked,
            faceIDChecked,
            findMyChecked,
            twoFactorChecked
        ].filter { $0 }.count
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Protezione del dispositivo")
                            .font(.headline)

                        Text("\(completed) controlli su 5 completati")
                            .foregroundStyle(.cyan)

                        ProgressView(value: Double(completed), total: 5)
                            .tint(.cyan)
                    }
                    .padding(.vertical, 8)
                }

                Section("Verifiche iPhone") {
                    Toggle("Ho verificato gli aggiornamenti iOS", isOn: $iosUpdateChecked)

                    Toggle("Ho impostato un codice sicuro", isOn: $passcodeChecked)

                    Toggle("Ho verificato Face ID", isOn: $faceIDChecked)

                    Toggle("Ho verificato Dov'è il mio iPhone", isOn: $findMyChecked)

                    Toggle("Ho attivato l'autenticazione a due fattori Apple", isOn: $twoFactorChecked)
                }

                Section("Dove effettuare i controlli") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Aggiornamenti iOS")
                            .font(.headline)

                        Text("Impostazioni → Generali → Aggiornamento software")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Codice e Face ID")
                            .font(.headline)

                        Text("Impostazioni → Face ID e codice")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Dov'è")
                            .font(.headline)

                        Text("Impostazioni → Il tuo nome → Dov'è")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Autenticazione Apple")
                            .font(.headline)

                        Text("Impostazioni → Il tuo nome → Accesso e sicurezza")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                Section {
                    Button("Azzera tutti i controlli") {
                        iosUpdateChecked = false
                        passcodeChecked = false
                        faceIDChecked = false
                        findMyChecked = false
                        twoFactorChecked = false
                    }
                    .foregroundStyle(.red)
                }

                Section {
                    Text("Le spunte sono verifiche dichiarate dall'utente. L'app non legge automaticamente le impostazioni interne di iOS e non certifica l'assenza di attacchi.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("iPhone Security")
        }
    }
}


// MARK: - Analisi locale dei link

private struct ExternalLinkResult: Decodable {
    struct Source: Decodable {
        let status: String
        let message: String?
        let malicious: Int?
        let suspicious: Int?
        let undetected: Int?
    }
    let verdict: String
    let googleSafeBrowsing: Source
    let phishDestroy: Source
    let checkedAt: String?
}

struct LinkScannerView: View {
    @AppStorage("sentinel.linkCheckEndpoint") private var endpoint = "https://zeroclick-security-lab.raffaellagranato89.workers.dev"
    @State private var linkText = ""
    @State private var isChecking = false
    @State private var result: ExternalLinkResult?
    @State private var errorMessage: String?

    private func checkOnline() async {
        let raw = linkText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parsed = URL(string: raw.contains("://") ? raw : "https://" + raw),
              let scheme = parsed.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              parsed.host != nil else {
            errorMessage = "Inserisci un indirizzo HTTP o HTTPS valido."
            return
        }
        guard let serviceURL = URL(string: endpoint.trimmingCharacters(in: .whitespacesAndNewlines)),
              serviceURL.scheme == "https",
              serviceURL.host != nil else {
            errorMessage = "Configura prima l'indirizzo HTTPS del servizio di verifica."
            return
        }

        isChecking = true
        result = nil
        errorMessage = nil
        defer { isChecking = false }

        do {
            var request = URLRequest(url: serviceURL)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.timeoutInterval = 45
            request.httpBody = try JSONSerialization.data(withJSONObject: ["url": parsed.absoluteString])
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                throw URLError(.badServerResponse)
            }
            result = try JSONDecoder().decode(ExternalLinkResult.self, from: data)
        } catch {
            errorMessage = "Verifica online non riuscita. Controlla il servizio e la connessione, poi riprova."
        }
    }

    private func sourceView(_ title: String, _ source: ExternalLinkResult.Source) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.headline)
            Text(source.status.uppercased())
                .font(.subheadline.bold())
                .foregroundStyle(source.status == "checked" ? .cyan : .orange)
            if let malicious = source.malicious {
                Text("Rilevamenti malevoli: \\(malicious)")
                    .font(.footnote)
            }
            if let suspicious = source.suspicious {
                Text("Rilevamenti sospetti: \\(suspicious)")
                    .font(.footnote)
            }
            if let undetected = source.undetected {
                Text("Non rilevati: \\(undetected)")
                    .font(.footnote)
            }
            if let message = source.message {
                Text(message).font(.footnote).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color.white.opacity(0.07))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Image(systemName: "network.badge.shield.half.filled")
                        .font(.system(size: 46))
                        .foregroundStyle(.cyan)
                        .frame(maxWidth: .infinity)
                    Text("Verifica online anti-phishing")
                        .font(.title2.bold())
                        .frame(maxWidth: .infinity)
                    Text("Il link viene inviato ai servizi esterni configurati per confrontarlo con i loro database di minacce. Non viene aperto sul dispositivo.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)

                    Text("Indirizzo del servizio sicuro (HTTPS)")
                        .font(.headline)
                    TextField("https://tuo-worker.example.workers.dev/check", text: $endpoint)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .padding()
                        .background(Color.white.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 10))

                    Text("Link da verificare")
                        .font(.headline)
                    TextField("https://esempio.it", text: $linkText, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .padding()
                        .background(Color.white.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 10))

                    Button {
                        Task { await checkOnline() }
                    } label: {
                        HStack {
                            if isChecking { ProgressView().tint(.black) }
                            Label(isChecking ? "Verifica in corso..." : "Verifica con i database esterni",
                                  systemImage: "shield.lefthalf.filled")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.cyan)
                        .foregroundStyle(.black)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .disabled(isChecking)

                    if let errorMessage {
                        Text(errorMessage).foregroundStyle(.orange).font(.footnote)
                    }
                    if let result {
                        Text(result.verdict)
                            .font(.headline)
                            .foregroundStyle(result.verdict.lowercased().contains("malicious") || result.verdict.lowercased().contains("unsafe") ? .red : .cyan)
                        sourceView("Google Safe Browsing", result.googleSafeBrowsing)
                        sourceView("PhishDestroy", result.phishDestroy)
                    }

                    Text("Privacy e limiti: il link completo viene trasmesso ai fornitori esterni quando premi Verifica. Evita link contenenti token privati o informazioni personali. I risultati possono essere incompleti o avere falsi positivi; nessun esito garantisce sicurezza.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding()
            }
            .navigationTitle("Link Security")
        }
    }
}

// MARK: - Analisi locale dei file

private struct FileScanRecord: Codable, Identifiable {
    var id: UUID
    var name: String
    var date: Date
    var size: Int64
    var sha256: String
    var status: String
    var details: String
}

struct FileScannerView: View {
    @State private var showingImporter = false
    @State private var records: [FileScanRecord] = Self.loadRecords()
    @State private var errorMessage: String?

    private static let storageKey = "sentinel.fileScanHistory"

    private static func loadRecords() -> [FileScanRecord] {
        guard let data = UserDefaults.standard.data(forKey: storageKey),
              let decoded = try? JSONDecoder().decode([FileScanRecord].self, from: data) else {
            return []
        }
        return decoded
    }

    private func saveRecords() {
        if let data = try? JSONEncoder().encode(records) {
            UserDefaults.standard.set(data, forKey: Self.storageKey)
        }
    }

    private func scan(_ url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
        }

        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let size = (attributes[.size] as? NSNumber)?.int64Value ?? 0
            let maximumSize: Int64 = 50 * 1024 * 1024
            guard size <= maximumSize else {
                errorMessage = "File troppo grande per l'analisi locale. Il limite attuale è 50 MB."
                return
            }
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            guard !data.isEmpty else {
                errorMessage = "Il file è vuoto e non può essere analizzato."
                return
            }
            let digest = SHA256.hash(data: data)
                .map { String(format: "%02x", $0) }
                .joined()

            let ext = url.pathExtension.lowercased()
            let signature = Self.signatureWarning(for: data, extension: ext)
            let executableTypes: Set<String> = [
                "app", "ipa", "pkg", "dmg", "mobileconfig",
                "sh", "command", "js", "jar", "apk", "exe", "dll"
            ]

            var status = "Nessun indicatore semplice rilevato"
            var details = "Il controllo ha calcolato l'hash SHA-256 e verificato alcuni indicatori di base. Non è una scansione antivirus."

            if let signature {
                status = "ATTENZIONE"
                details = signature
            } else if executableTypes.contains(ext) {
                status = "FILE DA VERIFICARE"
                details = "Il tipo di file può contenere codice eseguibile o configurazioni. Aprilo solo se ne conosci la provenienza."
            }

            let record = FileScanRecord(
                id: UUID(),
                name: url.lastPathComponent,
                date: Date(),
                size: size,
                sha256: digest,
                status: status,
                details: details
            )
            records.insert(record, at: 0)
            records = Array(records.prefix(100))
            saveRecords()
            errorMessage = nil
        } catch {
            errorMessage = "Impossibile leggere il file: \(error.localizedDescription)"
        }
    }

    private static func signatureWarning(for data: Data, extension ext: String) -> String? {
        let bytes = [UInt8](data.prefix(8))
        if ext == "pdf" && !data.starts(with: Data("%PDF-".utf8)) {
            return "L'estensione è PDF, ma la firma iniziale non corrisponde al formato PDF."
        }
        if ext == "png" && bytes != [137, 80, 78, 71, 13, 10, 26, 10] {
            return "L'estensione è PNG, ma la firma del file non corrisponde a PNG."
        }
        if ext == "jpg" || ext == "jpeg" {
            if bytes.count < 3 || bytes[0] != 0xFF || bytes[1] != 0xD8 || bytes[2] != 0xFF {
                return "L'estensione è JPEG, ma la firma iniziale non corrisponde a JPEG."
            }
        }
        if ext == "gif" && !data.starts(with: Data("GIF87a".utf8)) && !data.starts(with: Data("GIF89a".utf8)) {
            return "L'estensione è GIF, ma la firma iniziale non corrisponde a GIF."
        }
        if ext == "zip" && !(bytes.count >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4B && [0x03, 0x05, 0x07].contains(bytes[2]) && [0x04, 0x06, 0x08].contains(bytes[3])) {
            return "L'estensione è ZIP, ma la firma iniziale non corrisponde a ZIP."
        }
        if ext == "mp4" && !(data.count >= 8 && String(data: data[4..<8], encoding: .ascii) == "ftyp") {
            return "L'estensione è MP4, ma l'intestazione del file non corrisponde al formato MP4."
        }
        return nil
    }

    private func formattedSize(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("Controllo file sul dispositivo", systemImage: "doc.viewfinder")
                            .font(.headline)
                        Text("Seleziona un file salvato su iPhone. L'analisi avviene localmente: il contenuto non viene caricato su server.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Button {
                            showingImporter = true
                        } label: {
                            Label("Seleziona un file da analizzare", systemImage: "folder")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.cyan)
                    }
                    .padding(.vertical, 8)
                }

                if let errorMessage {
                    Section("Errore") {
                        Text(errorMessage)
                            .foregroundStyle(.red)
                    }
                }

                Section("Ultime analisi") {
                    if records.isEmpty {
                        Text("Non hai ancora analizzato file.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(records) { record in
                            VStack(alignment: .leading, spacing: 7) {
                                Text(record.name)
                                    .font(.headline)
                                    .lineLimit(2)
                                Text(record.status)
                                    .font(.subheadline.bold())
                                    .foregroundStyle(record.status == "ATTENZIONE" ? .red : (record.status == "FILE DA VERIFICARE" ? .orange : .green))
                                Text(record.details)
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                                Text("\(formattedSize(record.size)) • \(record.date.formatted(date: .abbreviated, time: .shortened))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text("SHA-256: \(record.sha256)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .textSelection(.enabled)
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 5)
                        }
                        .onDelete { offsets in
                            records.remove(atOffsets: offsets)
                            saveRecords()
                        }
                    }
                }

                Section {
                    Button(role: .destructive) {
                        records.removeAll()
                        saveRecords()
                    } label: {
                        Label("Cancella cronologia analisi", systemImage: "trash")
                    }
                    .disabled(records.isEmpty)
                }

                Section("Limiti importanti") {
                    Text("Il limite di lettura è 50 MB per contenere l'uso della memoria. Il controllo confronta alcune firme note e calcola SHA-256, ma NON è un antivirus: un file può avere una firma corretta ed essere comunque dannoso. iOS non consente a un'app normale di intercettare automaticamente tutti i download o di eseguire scansioni complete in background.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("File Security")
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: [.item],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first { scan(url) }
                case .failure(let error):
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
}
