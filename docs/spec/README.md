# Specifiche (WinCleaner)

Riferimenti: le funzioni pubbliche di CCleaner Pro (Controllo integrità, Pulizia personalizzata, Registro, Aggiornamento software, Strumenti: disinstallazione, avvio, plugin dei browser, analisi disco, ricerca duplicati, ripristino configurazione, cancellazione unità) e le scelte di sicurezza di MacCleaner. Nessun codice, testo o regola di Piriform è stato usato: le regole sono scritte da zero partendo dalla documentazione pubblica di Windows e dei programmi.

## Da Mac a Windows
| MacCleaner | WinCleaner |
|---|---|
| Cestino (`~/.Trash`) | Cestino per unità (`X:\$Recycle.Bin\<SID>`), coppie `$R`/`$I` versione 2 |
| `PinnedFileSystem` (`openat`, `O_NOFOLLOW`, `unlinkat`, `renameatx_np`) | `NtCreateFile` relativo all'handle padre con `FILE_OPEN_REPARSE_POINT`, `FileDispositionInformationEx` (POSIX), `FileRenameInformationEx` senza sostituzione |
| SIP | TrustedInstaller proprietario, Windows Resource Protection (`SfcIsFileProtected`) |
| `mchelper` + password di macOS | `wchelper.exe` + UAC, named pipe solo utente, verifica SHA-256 |
| `AllowedRoots` | `Roots.User/System/SystemItems/UserFiles`, `LeftoverFinder.AllowedRoots/SystemRoots` |
| Smart Care | Controllo integrità |
| Launch agent / login item | Chiavi Run e cartelle Esecuzione automatica (`StartupApproved`), attività pianificate, servizi |
| Sparkle / App Store / Homebrew | winget (`winget upgrade`, letto per posizione di colonna) |
| Bundle ID degli avanzi | Nome del programma, cartella di installazione, editore; mai dentro la cartella di un altro programma |
| Quarantena (`com.apple.quarantine`) | Mark of the Web (`Zone.Identifier`) |
| Full Disk Access | Non serve; le cartelle di sistema si leggono tramite l'helper |
| Monitor nella barra dei menu | Icona nell'area di notifica |
| `launchd` per le scansioni pianificate | Attività in Utilità di pianificazione, notifica con Windows App SDK |
| XProtect, Gatekeeper | Defender, SmartScreen, Security Center (WMI) |

## Moduli
- **Pulizia sistema** — `src/WinCleaner.Modules/Rules/system-junk.json` (regole Windows, sistema, app, sviluppo) + `BrowserCatalog` (cache per browser). Ogni regola: percorsi con token (`%LOCALAPPDATA%`…) e `*`, destinazione (contenuto o elemento), filtri di nome, età minima, rischio, preselezione, amministratore, processi che la sospendono, cartella sorella richiesta (per riconoscere le app Chromium/Electron), componente del percorso che nomina il programma proprietario.
- **Cestini** — elenco dai file `$I`, svuotamento per elemento.
- **Registro** — voci di disinstallazione senza programma (MSI: `MsiQueryProductState`), App Paths, SharedDLLs, MuiCache; solo file locali mancanti (le unità di rete o rimovibili scollegate non contano).
- **Analisi disco** — `GetFileInformationByHandleEx(FileIdExtdDirectoryInfo)`, parallelo fino a 20 livelli, dimensione allocata, hard link contati una volta.
- **File grandi e vecchi, Duplicati, Immagini simili, Installer, Avanzi** — come su Mac, con i file solo-cloud di OneDrive mai letti (leggerli li scaricherebbe).
- **Disinstallazione** — chiavi Uninstall (64/32 bit, utente), app Store (`PackageManager`), ultimo uso da UserAssist o Prefetch.
- **Privacy** — Chromium (History, Cookies, Web Data, Login Data, Sessions), Gecko (places, cookies, formhistory, logins.json, sessionstore), Recent, Jump List, MRU di Explorer, Appunti, profili Wi‑Fi (`netsh wlan export`, XML), ConsentStore per fotocamera, microfono e posizione.
- **Avvio automatico** — Run/RunOnce (utente, macchina, 32 bit), cartelle Esecuzione automatica, attività fuori da `\Microsoft\`, servizi automatici non Microsoft; firma Authenticode senza rete.
- **Manutenzione** — elenco chiuso (`MaintenanceTask`), comandi fissi.
- **Protezione** — controlli euristici con motivo, nessuna rimozione automatica; analisi rapida delegata a Defender (`MpCmdRun -Scan -ScanType 1`).

## Verifiche fatte sul mini PC
- Explorer mostra gli elementi spostati nel Cestino nella posizione originale (test automatico).
- Pulizia sistema: ~0,5 s per 800 elementi; analisi disco: 437.000 file in ~7 s (N95).
- Helper: avvio tramite PowerShell elevata con copia verificata, collegamento e rifiuto di System32, WindowsApps e `C:\Users`.
