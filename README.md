# WinCleaner

App Windows personale per pulire e mantenere il PC, ispirata alle funzioni di CCleaner Pro e costruita come la gemella [MacCleaner](../maccleaner). Le scelte di progetto sono in `docs/spec/`.

## Requisiti
- Windows 10 2004 o successivo, Windows 11 (x64 o ARM64)
- .NET 10 SDK per compilare (`winget install Microsoft.DotNet.SDK.10`). Visual Studio non serve.

## Struttura
| Progetto | Contenuto |
|---|---|
| `src/WinCleaner.Core` | File system tramite handle, rimozione sicura, Cestino, regole, registro di sistema, firme digitali |
| `src/WinCleaner.Modules` | Moduli: pulizia, file, programmi, privacy, avvio, manutenzione, protezione, registro, helper |
| `src/WinCleaner.App` | App WinUI 3 (`WinCleaner.exe`) |
| `src/WinCleaner.Helper` | `wchelper.exe`, l'unica parte che gira come amministratore |
| `src/WinCleaner.Cli` | `wccli.exe`, per provare le scansioni dal terminale |
| `tests/WinCleaner.Tests` | Test xUnit (girano su Windows) |

## Comandi
Dal Mac, con il PC Windows raggiungibile via SSH (`WC_HOST`, predefinito `blackframe-minipc`):
```bash
scripts/remote.sh dotnet test tests/WinCleaner.Tests -p:Platform=x64      # test
scripts/remote.sh dotnet build WinCleaner.slnx -p:Platform=x64            # tutto
scripts/remote.sh "powershell -ExecutionPolicy Bypass -File scripts\publish.ps1"   # cartella pronta in artifacts\
```
Direttamente su Windows:
```powershell
dotnet test tests\WinCleaner.Tests -p:Platform=x64
powershell -ExecutionPolicy Bypass -File scripts\publish.ps1      # artifacts\WinCleaner-x64
powershell -ExecutionPolicy Bypass -File scripts\install.ps1      # in Program Files, con voce in App installate
```
Installazione su un altro PC:
1. Sul PC di sviluppo: `powershell -ExecutionPolicy Bypass -File scripts\publish.ps1 -Setup` crea `artifacts\WinCleaner-Setup-<versione>-x64.exe` (circa 100 MB; `-Arch arm64` per i PC ARM). Serve Inno Setup 6 (`winget install JRSoftware.InnoSetup`).
2. Copia il setup sull'altro PC e aprilo: procedura guidata classica, chiede l'amministratore, installa in `C:\Program Files\WinCleaner`, aggiunge WinCleaner al menu Start (e, se scelto, al desktop) e ad App installate. Per aggiornare basta lanciare il setup nuovo sopra quello vecchio.
3. Per toglierlo: Impostazioni → App → WinCleaner → Disinstalla. Toglie anche l'analisi pianificata e l'avvio con Windows; i dati in `%LOCALAPPDATA%\WinCleaner` restano.

In alternativa, `publish.ps1 -Zip` crea uno zip con `Installa.cmd` (installazione via script, senza procedura guidata).

Non serve installare .NET o altro: l'app contiene tutto. I file sono firmati (vedi Sicurezza); con un certificato autofirmato SmartScreen può comunque mostrare «Windows ha protetto il PC» al primo avvio del setup: «Ulteriori informazioni» → «Esegui comunque».

Prova delle scansioni (sola lettura, salvo `clean`, che di default è una prova):
```powershell
wccli scan system-junk|recycle-bin|registry|large-old-files|duplicates|similar-images|installers|orphans [--items]
wccli clean system-junk --mode dry|recycle|delete
wccli lens C:\ | apps | leftovers <nome> | updates | privacy | startup | protection [--evidence --all --report] | processes | signatures | monitor
```

## Funzioni
| Area | Cosa fa |
|---|---|
| Controllo integrità | Pulizia, protezione, aggiornamenti, avvio e disco in un clic. Pulisce solo i file preselezionati dell'utente, dopo conferma. |
| Pulizia sistema | Temporanei, cache di miniature, icone e shader, segnalazioni errori, dump, log, Windows Update, Prefetch, avanzi di installazione di Windows, cache dei browser (Chrome, Edge, Brave, Vivaldi, Opera, Arc, Firefox e derivati), delle app Electron, di Teams, Spotify, Steam, Adobe e degli strumenti di sviluppo. |
| Cestini | Contenuto del Cestino di ogni unità, con posizione originale e data. |
| Registro | Solo voci verso programmi e file che non esistono più: voci di disinstallazione, App Paths, SharedDLLs, cache MUI. |
| Analisi disco | Mappa ad albero dello spazio, veloce (handle e ID dei file, in parallelo). |
| File | File grandi e vecchi, download non usati, duplicati, immagini simili, installer già usati. |
| Programmi | Disinstallazione con ricerca degli avanzi, app dello Store, aggiornamenti con winget, avanzi di programmi già rimossi. |
| Privacy | Cronologia, cookie, download, moduli, password (solo conteggio), sessioni dei browser; file recenti, Jump List, ricerche di Explorer, Appunti, reti Wi‑Fi; app che hanno usato fotocamera, microfono e posizione. |
| Protezione | Defender (criteri, esclusioni, minacce recenti, ASR), difese e impostazioni (firewall, UAC, SmartScreen, LSASS, WDigest, BitLocker, aggiornamenti, estensioni nascoste, AutoPlay, SMBv1, accesso remoto, account, login automatico, PowerShell, macro di Office), persistenza (Run, attività anche nascoste, servizi e driver, Winlogon, IFEO, AppInit, WMI, BITS, COM, Active Setup, LSA, shell, provider, profili PowerShell, Office), programmi recenti, browser (estensioni, criteri forzati, dirottamenti, Firefox), certificati radice, rete (hosts, proxy, DNS, regole firewall), processi (CPU sostenuta, nomi di sistema fuori posto, LOLBin, iniezioni, connessioni), firme (LOLDrivers, hash MalwareBazaar, YARA). Ogni avviso ha evidenze e "nuovo dall'ultimo controllo"; controllo approfondito con l'helper in sola lettura; quarantena, correzioni del registro con backup, analisi mirata di Defender, rapporto Markdown. |
| Attività | Processi in tempo reale con CPU, memoria, disco, connessioni, firma e giudizio di Protezione; avviso nell'area di notifica quando un processo non Microsoft satura un core per oltre un minuto. |
| Quarantena | File messi da parte da Protezione: senza permessi di esecuzione, nascosti, con Zone.Identifier; ripristino ed eliminazione (di sistema tramite l'helper). |
| Prestazioni | Avvio automatico (come Gestione attività), attività pianificate, servizi; manutenzione: DNS, memoria, icone, Esplora risorse, Pulizia di Windows (Windows.old), DISM, SFC, Ottimizzazione recapito, ottimizzazione unità, punto di ripristino, cancellazione dello spazio libero. |
| Altro | Icona nell'area di notifica con CPU, memoria, disco e batteria; analisi pianificata con notifica; avvio con Windows. |

Fuori dal perimetro, di proposito: aggiornamento dei driver (serve un database proprietario e può rendere il PC instabile), pulizia del registro "aggressiva" (Microsoft la sconsiglia), antivirus proprio (c'è Defender).

## Sicurezza
- Di default i file vanno nel **Cestino** (restano ripristinabili da Esplora risorse). C'è la modalità **Prova** che non rimuove nulla.
- Si rimuove solo **dentro cartelle consentite** (`Roots`), mai la cartella stessa. I percorsi devono essere percorsi locali semplici: niente `\\?\`, UNC, flussi alternativi (`file:stream`), `.` o `..`, nomi che finiscono con punto o spazio.
- **Nessuna operazione per percorso.** La cartella consentita viene aperta e ogni cartella sotto viene aperta relativamente alla precedente (`NtCreateFile` con handle radice), senza mai seguire junction, link simbolici o punti di montaggio: se una cartella viene scambiata con un collegamento mentre l'operazione è in corso, l'operazione fallisce invece di finire altrove. I file si eliminano tramite il loro handle (semantica POSIX) e si spostano nel Cestino rinominando l'handle nella cartella del Cestino, senza mai sostituire un elemento esistente; accanto viene scritto il file `$I` nel formato di Explorer, così "Ripristina" funziona.
- Dentro una cartella da eliminare i collegamenti vengono tolti come collegamenti: il loro contenuto non viene mai letto, misurato o cancellato.
- I file di proprietà di **TrustedInstaller** e quelli protetti da **Windows Resource Protection** vengono rifiutati. I dati di WinCleaner (log, backup) non vengono mai puliti.
- File in uso: vengono lasciati al loro posto e contati.
- Le cache di un programma aperto vengono saltate (browser, Teams, Spotify, le app Electron con il nome della loro cartella…) e il controllo viene ripetuto subito prima della pulizia.
- **Registro di sistema**: si tocca solo un elenco chiuso di posti (chiavi dei programmi sotto `Software`, e liste di Windows come Uninstall, App Paths, Run, SharedDLLs, MuiCache, cronologie di Explorer); mai `HKLM\SYSTEM`, `Classes`, `Policies` o la chiave `Microsoft`. Ogni chiave viene esportata in un file `.reg` prima di toglierla (cartella `%LOCALAPPDATA%\WinCleaner\Backups`).
- **Browser**: si cancellano righe dai database solo a browser chiuso, dopo una copia completa fatta da SQLite (`VACUUM INTO`, include le modifiche nel file `-wal`), riletta e messa nel Cestino. Le istruzioni per tabelle assenti in quella versione del browser vengono saltate, così la transazione non fallisce a metà. Le password non vengono mai lette.
- **Duplicati**: sono preselezionate solo le copie nei Download; prima di pulire viene ricontrollato che la copia che resta esista e sia identica. Non si può togliere la copia da tenere né tutte le copie di un gruppo.
- **Disinstallazione**: usa il programma di disinstallazione del produttore (o `msiexec /x`), chiude il programma prima e aspetta anche le copie del disinstallatore lanciate da `%TEMP%`. Gli avanzi si cercano con nomi esatti (programma, cartella, editore), mai dentro la cartella di un altro programma; sono preselezionati solo la cartella rimasta, la voce rimasta in App installate e i collegamenti rotti. L'elenco è bloccato durante l'operazione.
- **Installer**: preselezionati solo se Windows li ha segnati come scaricati da internet (Mark of the Web) e lo stesso programma è installato in versione uguale o più recente.
- **Avvio automatico**: disattivare usa le chiavi `StartupApproved`, come Gestione attività, ed è sempre reversibile. Le attività sotto `\Microsoft\` e i servizi di Microsoft non vengono mostrati né toccati.
- **Helper di sistema** (`wchelper.exe`): è l'unica parte che gira come amministratore, con una sola richiesta UAC per sessione. Comunica su una named pipe accessibile solo all'utente, con un'unica connessione; l'app verifica che il processo collegato esegua un file con lo SHA-256 atteso, e l'helper verifica che la pipe appartenga a `WinCleaner.exe` nella sua stessa cartella, avviato dallo stesso utente, e nella versione pubblicata che `WinCleaner.dll` abbia lo SHA-256 compilato dentro l'helper da `publish.ps1` (`wchelper.exe --identity` lo mostra): un altro programma che lo avviasse con una richiesta UAC a nome di WinCleaner viene rifiutato. Accetta un elenco chiuso di operazioni e ricontrolla tutto da sé: cartelle di sistema consentite, elenco di cartelle condivise mai toccate (WindowsApps, Common Files, `ProgramData\Microsoft`…), TrustedInstaller, WRP, elenco del registro; le cartelle di programmi ancora installati, o da cui gira un processo, non si toccano; attività, servizi, voci di avvio e reti Wi‑Fi devono essere tra quelli che l'helper stesso trova sul sistema. Tutto ciò che scrive da amministratore (log, backup `.reg`, quarantena di sistema) sta in `C:\ProgramData\WinCleaner`, in cartelle create con permessi espliciti per soli amministratori e ricontrollate a ogni uso (proprietario, DACL, niente junction). Gli strumenti di Windows che avvia partono con un ambiente ripulito (niente variabili del profiler .NET né startup hook, `PSModulePath` e `PATH` limitati alle cartelle di sistema), Defender e le sottoscrizioni WMI si pilotano con metodi WMI e mai con una stringa PowerShell, le DLL si caricano solo dalla sua cartella e da System32. Si chiude dopo 10 minuti senza richieste. Fuori da Program Files (sviluppo) l'helper funziona ma scrive nel log che la cartella non è protetta.
- **Protezione (M7, `docs/spec/protection-upgrade.md`)**: la scansione standard non chiede mai l'amministratore. Il controllo approfondito usa una sola operazione dell'helper di sola lettura (`CollectSystemEvidence`): query WMI e comandi fissi. Le modifiche al registro passano da un elenco esatto di voci (`ProtectionRegistry`), con file `.reg` prima di ogni cambio; i valori che Windows richiede (Shell, Userinit, AppInit_DLLs) vengono riportati al valore predefinito, non cancellati. La quarantena sposta i file tramite handle (`SafeRemover.MoveInto`), toglie i permessi di esecuzione, aggiunge `Zone.Identifier`, sempre lavorando su handle e mai su percorsi; il ripristino rimette un elemento solo dentro le cartelle da cui la quarantena può prendere, aprendo la destinazione un nome alla volta senza seguire collegamenti, e un record dell'indice che non punta alla propria cartella viene ignorato. La quarantena di sistema sta in `ProgramData\WinCleaner\Quarantine` (solo amministratori) tramite l'helper. L'helper termina un processo solo se esegue ancora l'immagine indicata e mai i processi critici o i componenti firmati di Windows. Le firme: un file senza firma dentro `C:\Windows` viene cercato nei cataloghi di Windows (è così che sono firmati i componenti), non creduto per il percorso: `Windows\Temp`, `Tasks` e le altre cartelle scrivibili dagli utenti non godono di fiducia; «Microsoft» vale solo quando la catena del certificato finisce in una radice Microsoft, non quando il nome inizia con Microsoft. Regole YARA, hash e LOLDrivers non vengono scaricati: l'utente li aggiunge dalle Impostazioni e confronta lo SHA-256 mostrato; `yara64.exe` ufficiale va messo nella stessa cartella. Le regole e `yara64.exe` si confermano come amministratore (un clic nelle Impostazioni): i loro SHA-256 finiscono in `ProgramData\WinCleaner\Pins`, che solo gli amministratori scrivono, e a ogni scansione un file cambiato viene segnalato e non usato (un `yara64.exe` cambiato è un Pericolo e non parte). «Ignora» nasconde solo avvisi e informazioni, mai un Pericolo, e la pagina mostra sempre quanti avvisi sono stati ignorati e quanti editori resi fidati.
- Ogni operazione finisce nel registro `%LOCALAPPDATA%\WinCleaner\Logs\operations.log` (quelle dell'helper in `C:\ProgramData\WinCleaner\Helper\Logs`).
- **Esecuzione di strumenti**: ogni programma esterno (reg, netsh, winget, yara, MpCmdRun…) parte con il percorso assoluto, argomenti separati e l'ambiente ripulito dalle variabili con cui un processo a livello utente può far caricare codice (profiler .NET, startup hook, moduli PowerShell del profilo). «Apri» nell'analisi disco apre solo documenti e media, mai eseguibili o script.
- **Pubblicazione e firma**: `publish.ps1` ripristina i pacchetti in modalità bloccata (`packages.lock.json`), si ferma se un pacchetto ha un avviso di sicurezza, e firma con Authenticode app, helper, DLL del progetto, setup e disinstallatore con il certificato «WinCleaner Code Signing» del PC di compilazione (`scripts\new-signing-cert.ps1` lo crea una volta, chiave non esportabile; `-SignThumbprint` per usarne un altro, `-NoSign` solo per prove). L'impronta del certificato e lo SHA-256 di `WinCleaner.dll` vengono compilati dentro `wchelper.exe`, che serve solo un `WinCleaner.exe` con quella firma intatta; `install.ps1` rifiuta file non firmati o modificati dopo la firma. Un certificato autofirmato dà integrità e autenticazione dell'helper; non dà la reputazione SmartScreen. Le release ufficiali vengono invece firmate da SignPath (vedi «Code signing policy»): il workflow compila con `-NoSign -ExpectedSigner <impronta>`, così l'helper è legato al certificato di SignPath, manda i file a firmare e costruisce il setup dai file firmati (`-SetupOnly`).

## Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

Releases are built by [GitHub Actions](.github/workflows/release.yml) from a `v<version>` tag of this repository and signed by SignPath after manual approval; builds made on a developer's PC are never signed with that certificate. The full policy, the team roles, the privacy statement (WinCleaner sends no data) and the uninstall instructions are in [docs/code-signing-policy.md](docs/code-signing-policy.md). Downloads: [Releases](https://github.com/nicomil/wincleaner/releases).

## Licenza

MIT, vedi [LICENSE](LICENSE).

## Stato
| Milestone | Stato |
|---|---|
| M0: ambiente (.NET 10 sul mini PC, sync via SSH) | fatto |
| M1: core (handle, Cestino, regole), pulizia sistema, cestini | fatto |
| M2: analisi disco, file grandi e vecchi, duplicati, immagini simili | fatto |
| M3: programmi, avanzi, aggiornamenti winget, installer, orfani | fatto |
| M4: privacy, avvio automatico, manutenzione, protezione, registro, helper | fatto |
| M5: app WinUI 3, area di notifica, pianificazione, impostazioni | fatto (da provare a schermo) |
| M6: installazione in Program Files | fatto (setup.exe con Inno Setup, o script PowerShell) |
| M7: Protezione avanzata (Defender, persistenza, processi, quarantena, firme) | fatto |

149 test automatici coprono le parti di sicurezza (junction nel percorso e dentro le cartelle, file in uso, sola lettura, Cestino visibile in Explorer, backup del registro e dei database, regole dentro le radici, limiti dell'helper, cartelle solo-amministratori, record di quarantena falsi, chiamante dell'helper, ambiente ripulito, fiducia per catalogo e non per percorso).
