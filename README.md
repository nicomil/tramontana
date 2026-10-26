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
Prova delle scansioni (sola lettura, salvo `clean`, che di default è una prova):
```powershell
wccli scan system-junk|recycle-bin|registry|large-old-files|duplicates|similar-images|installers|orphans [--items]
wccli clean system-junk --mode dry|recycle|delete
wccli lens C:\ | apps | leftovers <nome> | updates | privacy | startup | protection | monitor
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
| Protezione | Antivirus, protezione in tempo reale e anti-manomissione, firewall, UAC, SmartScreen, Avvio protetto, Desktop remoto, avvio sospetto, estensioni dei browser, file hosts, proxy, dispositivi con problemi; analisi rapida con Defender. |
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
- **Helper di sistema** (`wchelper.exe`): è l'unica parte che gira come amministratore, con una sola richiesta UAC per sessione. Comunica su una named pipe accessibile solo all'utente, con un'unica connessione; l'app verifica che il processo collegato esegua un file con lo SHA-256 atteso, l'helper verifica che la pipe appartenga al processo che l'ha avviato. Accetta un elenco chiuso di operazioni e ricontrolla tutto da sé: cartelle di sistema consentite, elenco di cartelle condivise mai toccate (WindowsApps, Common Files, `ProgramData\Microsoft`…), TrustedInstaller, WRP, elenco del registro; attività, servizi, voci di avvio e reti Wi‑Fi devono essere tra quelli che l'helper stesso trova sul sistema. Se l'app non è in Program Files, una Windows PowerShell elevata copia l'helper in una cartella nuova sotto `C:\Windows\Temp` accessibile solo ad amministratori e SYSTEM, ne verifica lo SHA-256 e solo allora esegue quella copia.
- Ogni operazione finisce nel registro `%LOCALAPPDATA%\WinCleaner\Logs\operations.log`.

## Stato
| Milestone | Stato |
|---|---|
| M0: ambiente (.NET 10 sul mini PC, sync via SSH) | fatto |
| M1: core (handle, Cestino, regole), pulizia sistema, cestini | fatto |
| M2: analisi disco, file grandi e vecchi, duplicati, immagini simili | fatto |
| M3: programmi, avanzi, aggiornamenti winget, installer, orfani | fatto |
| M4: privacy, avvio automatico, manutenzione, protezione, registro, helper | fatto |
| M5: app WinUI 3, area di notifica, pianificazione, impostazioni | fatto (da provare a schermo) |
| M6: installazione in Program Files | fatto (script PowerShell) |

93 test automatici coprono le parti di sicurezza (junction nel percorso e dentro le cartelle, file in uso, sola lettura, Cestino visibile in Explorer, backup del registro e dei database, regole dentro le radici, limiti dell'helper).
