# SignPath Foundation: domanda di firma gratuita

Da compilare su https://signpath.org/apply (modulo HubSpot, in inglese). Testi pronti da incollare.

## Prerequisiti (spuntare prima di inviare)

- [x] Repository pubblico con licenza OSI: MIT (`LICENSE`).
- [x] Politica di firma pubblicata: `docs/code-signing-policy.md`, linkata dal README ("Code signing policy") e dalle note di ogni release.
- [x] Build automatica su GitHub Actions (`.github/workflows/release.yml`), nessuna build locale firmata.
- [x] Release pubblicata nel formato da firmare: `Tramontana-Setup-<versione>-x64.exe` su https://github.com/nicomil/tramontana/releases
- [x] Istruzioni di disinstallazione e avvisi prima delle modifiche al sistema (nella politica e nell'app).
- [x] Dichiarazione sulla privacy (nella politica: nessun dato inviato).
- [ ] **Autenticazione a due fattori attiva sull'account GitHub `nicomil`** (Settings → Password and authentication). Obbligatoria.
- [ ] Indirizzo email raggiungibile per le domande dei revisori (1-2 settimane di attesa tipiche).

## Campi del modulo

**Project name**: Tramontana

**Repository URL**: https://github.com/nicomil/tramontana

**Nota (28 ottobre 2026, sera)**: la domanda è stata inviata con il nome WinCleaner e il repository `nicomil/wincleaner`; dalla 0.3 il progetto si chiama Tramontana e il repository `nicomil/tramontana` (GitHub reindirizza il vecchio URL). Alla prima email di SignPath rispondere segnalando il nuovo nome, così progetto e certificato nascono già con quello.

**Project home page**: https://nicomil.github.io/tramontana/ (inviato nella domanda: https://github.com/nicomil/wincleaner)

**Download / release page**: https://github.com/nicomil/tramontana/releases

**Code signing policy URL**: https://github.com/nicomil/tramontana/blob/main/docs/code-signing-policy.md

**Privacy policy URL**: https://github.com/nicomil/tramontana/blob/main/docs/code-signing-policy.md#privacy-policy

**License**: MIT

**Build system**: GitHub Actions (GitHub-hosted runners, `windows-latest`)

**Artifacts to sign**: Windows installer (`Tramontana-Setup-<version>-x64.exe`, Inno Setup) and the executables and libraries inside it (`Tramontana.exe`, `trhelper.exe`, `Tramontana.Core.dll`, `Tramontana.Modules.dll`), produced by the release workflow.

**Project description** (incollare):

> Tramontana is a free, open-source cleaning and maintenance app for Windows 10 and 11 (WinUI 3, .NET 10), in the spirit of CCleaner: system and browser cleanup, disk space analysis, duplicates, leftovers of uninstalled programs, startup entries, Windows updates through winget, privacy traces and a "Protection" page that checks Defender status, persistence points, running processes and file signatures. It is designed to be safe by construction: files go to the Recycle Bin by default, every file operation works on handles (no symlink/junction following), registry keys are backed up before removal, and the only elevated component (trhelper.exe) accepts a closed list of operations and verifies the caller's hash and signature. The app has no telemetry and sends no data. It is distributed as an Inno Setup installer built by GitHub Actions; a code signature from a publicly trusted certificate is what the project needs to pass SmartScreen on users' PCs, which is the reason for this application. The source is in Italian for UI strings and documentation, with an English code signing policy.

**Why code signing matters for this project** (se chiesto):

> The installer and the elevated helper run with administrator rights; a trusted signature lets users (and Windows SmartScreen) verify that what they run is exactly what the public CI built from the public repository. The helper also pins the signer's certificate: a signed Tramontana.exe is the only client it will serve.

**Team**: Nicola Milella (GitHub `nicomil`): author, reviewer and approver (single-maintainer project).

**Checkboxes**: accettare le condizioni (https://signpath.org/terms): niente codice proprietario, niente strumenti di attacco, revisione delle pull request esterne, approvazione manuale di ogni richiesta di firma, MFA per tutti i membri.

## Dopo l'approvazione

SignPath invia i dati dell'organizzazione. Da fare:

1. In SignPath: creare il progetto `tramontana`, collegare il Trusted Build System "GitHub.com", creare le due artifact configuration incollando `docs/signpath/app-files.xml` (slug `app-files`) e `docs/signpath/setup.xml` (slug `setup`), creare la signing policy `release-signing` (approvazione manuale) e un utente CI con permesso *Submitter*, poi generare il suo API token.
2. Leggere l'impronta SHA-1 del certificato nella pagina del progetto (o da un file firmato di prova con `Get-AuthenticodeSignature`).
3. Su GitHub (Settings → Secrets and variables → Actions):
   - variabili: `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG` (= `tramontana`), `SIGNPATH_SIGNER_THUMBPRINT`;
   - segreto: `SIGNPATH_API_TOKEN`.
4. Creare un tag `v<versione>` (uguale a `Directory.Build.props`): il workflow compila, chiede la prima firma (file), costruisce il setup, chiede la seconda firma (setup) e pubblica la release. Ogni richiesta va approvata nell'interfaccia SignPath entro 2 ore (timeout del workflow), altrimenti rilanciare il workflow.
5. Quando SignPath rinnova il certificato, aggiornare `SIGNPATH_SIGNER_THUMBPRINT`: il passo "Put the signed files in place" si ferma con un messaggio esplicito se l'impronta non corrisponde.

Senza le variabili impostate il workflow pubblica comunque una pre-release non firmata: è ciò che serve per soddisfare il requisito "progetto già rilasciato".
