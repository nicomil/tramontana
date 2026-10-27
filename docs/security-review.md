# Security review di WinCleaner

Data: 27 ottobre 2026. Versione esaminata: 0.2.0 (commit `bdc0abc` più le modifiche non ancora committate a `publish.ps1`, `README.md`, `installer/`).

Metodo: lettura integrale del codice sorgente (Core, Modules, App, Helper, Cli), degli script di pubblicazione e installazione, del manifesto Inno Setup e dei test. Nessuna esecuzione dinamica: le prove pratiche indicate sotto vanno fatte sul PC Windows.

## Stato delle correzioni (27 ottobre 2026)

Tutte le trovate sono state corrette nel codice lo stesso giorno della review, con test (`tests/WinCleaner.Tests/HardeningTests.cs`) e prove sul PC Windows: handshake dell'helper riuscito dall'app e rifiutato da una pipe creata da PowerShell; cartelle di `ProgramData\WinCleaner` con DACL di soli amministratori; 141 test verdi; `publish.ps1` con restore bloccato, audit dei pacchetti, firma Authenticode di ogni binario e del setup (`Set-AuthenticodeSignature`, nessun SDK richiesto), hash e firma dell'app verificati nell'helper, `install.ps1` che rifiuta una DLL alterata (provato con un byte cambiato: «modificato dopo la firma») e installa la build firmata in Program Files; un test verifica che l'app installata superi i controlli dell'helper. La firma usa un certificato creato sul PC di compilazione (`scripts\new-signing-cert.ps1`, chiave non esportabile): dà integrità dei file e autenticazione del chiamante dell'helper, che era il punto di sicurezza; la reputazione SmartScreen richiede invece un certificato di una CA pubblica o di Azure Trusted Signing, che si innesta senza altre modifiche.

| ID | Stato | Come |
|---|---|---|
| C1 | Corretto | `HelperIdentity`: l'helper serve solo `WinCleaner.exe` nella sua cartella, stesso utente, e nella build pubblicata solo la `WinCleaner.dll` con l'hash compilato dentro (`publish.ps1`, `wchelper.exe --identity`). Bootstrap da `Windows\Temp` eliminato. `Remove` e `Quarantine` rifiutano le cartelle di programmi installati o in esecuzione. Idle 10 minuti. |
| C2 | Corretto | `SecureFolder`: `ProgramData\WinCleaner` e la quarantena creati con DACL esplicita e verificati a ogni uso; `Quarantine` lavora solo su handle (`Lock`/`Unlock`, `OpenStream`, `SetDacl`), `Restore` controlla radici e apre la destinazione per componenti senza seguire reparse point, i record che non puntano alla propria cartella vengono ignorati. |
| H1 | Corretto | `DataFolders`: nell'helper log e backup vanno in `ProgramData\WinCleaner\Helper` (solo amministratori). |
| H2 | Corretto | `ProcessEnvironment.Sanitize` su ogni processo avviato; `StartupHookSupport=false`; l'helper rifiuta di partire se trova variabili di hook nel proprio ambiente; Defender, WMI, TPM, processi e punto di ripristino tramite WMI invece di PowerShell. |
| H3 | Corretto | Niente più stringhe PowerShell con dati: metodi WMI (`MSFT_MpPreference.Remove/Set`, `ManagementObject.Delete`), valore passato via `$env:` nell'unico fallback, whitelist dei caratteri, esclusione verificata nell'elenco di Defender. |
| H4 | Corretto | Certificato di code signing del PC di compilazione (`new-signing-cert.ps1`), firma automatica in `publish.ps1` di app, DLL, helper, setup e disinstallatore; impronta del firmatario compilata nell'helper (`Signatures.IsSignedBy`); `install.ps1` rifiuta file non firmati o alterati. Per SmartScreen basta sostituire il certificato con uno di CA pubblica. |
| M1 | Corretto | `Signatures.VerifyCatalog` (CryptCATAdmin*, WinVerifyTrust con catalogo); la fiducia per percorso resta solo per System32, SysWOW64, WinSxS e simili, mai per `Windows\Temp` o `Tasks`; i servizi si giudicano dalla firma. |
| M2 | Corretto | `SetDefaultDllDirectories` all'avvio dell'helper; `DeleteWiFi` non apre più SQLite; copia in Temp eliminata. |
| M3 | Corretto | `RulePins`: SHA-256 di regole e `yara64.exe` confermati tramite l'helper in `ProgramData\WinCleaner\Pins` (scrivibile solo da amministratori); un file cambiato viene segnalato e non usato, `yara64.exe` non confermato o cambiato non parte. «Ignora» non nasconde mai un Pericolo (scanner, rapporto, interfaccia). La pagina mostra avvisi ignorati ed editori fidati. |
| M4 | Corretto | `IsMicrosoft` = catena fino a una radice Microsoft nota, o subject Microsoft sotto una radice fidata a livello macchina (mai solo utente). |
| M5 | Corretto | «Apri» nell'analisi disco solo per documenti e media. |
| L1–L9 | Corretti | Duplicati e JSON malformato nell'helper; `SystemDrive`/`Public` dalla cartella Windows e dalla shell; radici fisse per Privacy e Avvio; `SqliteConnectionStringBuilder`; `packages.lock.json` + `NuGetAudit` + audit nel publish; idle ridotto. |

## Premessa onesta

Nessun programma che cancella file, modifica il registro ed esegue operazioni come amministratore può essere «sicuro al 100%». L'obiettivo realistico, che questa review usa come metro, è un altro: **WinCleaner non deve mai diventare il mezzo con cui un malware o un utente non privilegiato ottiene qualcosa che altrimenti non avrebbe**, e non deve mai danneggiare il sistema su cui gira. Con questo metro la base dell'app è buona (vedi la sezione «Cosa è fatto bene»), ma ci sono due difetti critici nel perimetro dell'helper elevato che vanno corretti prima di installare l'app su macchine che non siano quella di sviluppo.

## Modello di minaccia usato

1. **Malware già presente a livello utente** (il caso tipico di un PC da pulire). Gira con i diritti dell'utente, non è amministratore, può scrivere ovunque l'utente possa scrivere (`%LOCALAPPDATA%`, `%TEMP%`, `C:\ProgramData` per creare file, `HKCU`), può osservare e reagire alle operazioni dell'app. Vuole diventare amministratore o neutralizzare le difese.
2. **Dati ostili analizzati dall'app**: nomi di file, voci di registro, righe di comando, database dei browser, output di strumenti, campioni malware letti da YARA.
3. **Catena di distribuzione**: zip o setup copiati fra PC, cartella di installazione, dipendenze NuGet.

Le gravità seguono questa scala: **Critica** = un processo a livello utente ottiene esecuzione o scrittura arbitraria come amministratore; **Alta** = lo stesso risultato ma con una condizione aggiuntiva (configurazione non predefinita, interazione dell'utente); **Media** = aggira le difese o indebolisce in modo concreto una garanzia dichiarata; **Bassa** = robustezza o buona pratica.

## Riepilogo

| ID | Gravità | Titolo |
|---|---|---|
| C1 | Critica | L'helper elevato si fida di qualunque processo lo avvii |
| C2 | Critica | La quarantena di sistema sta in una cartella scrivibile dagli utenti e il ripristino non controlla la destinazione |
| H1 | Alta | L'helper scrive log e backup in `%LOCALAPPDATA%` da elevato |
| H2 | Alta | PowerShell e .NET elevati ereditano l'ambiente dell'utente (moduli, profiler, startup hooks) |
| H3 | Alta | Injection PowerShell con virgolette tipografiche nelle operazioni Defender e WMI |
| H4 | Alta | Nessuna firma del codice su app, helper e setup |
| M1 | Media | «Dentro C:\Windows» viene trattato come firmato Microsoft |
| M2 | Media | DLL hijacking dell'helper quando gira dalla copia in `C:\Windows\Temp` |
| M3 | Media | Lo stato di Protezione (impostazioni, baseline, regole, yara64.exe) è manomettibile dallo stesso malware che dovrebbe trovare |
| M4 | Media | Un editore è «Microsoft» se il nome inizia con «Microsoft» |
| M5 | Media | «Apri» nell'analisi disco esegue il file scelto |
| L1–L9 | Bassa | Robustezza, dipendenze, dettagli di implementazione |

## Trovate critiche

### C1. L'helper elevato si fida di qualunque processo lo avvii

**Dove**: `src/WinCleaner.Modules/Helper/HelperClient.cs:63-71`, `src/WinCleaner.Helper/Program.cs:16-21`, `src/WinCleaner.Modules/Helper/HelperService.cs` (tutte le operazioni).

**Problema.** L'app verifica che il processo collegato alla pipe sia davvero `wchelper.exe` (hash SHA-256). Il contrario non avviene: l'helper controlla solo che il server della pipe abbia il PID passato in `--parent`, e quel PID lo sceglie chi lo avvia. Un programma qualsiasi a livello utente può quindi creare una pipe `WinCleaner-<guid>`, lanciare `wchelper.exe` con `runas` e aspettare che l'utente accetti la richiesta UAC, che mostra «wchelper.exe» di WinCleaner (editore sconosciuto, perché non firmato). Da quel momento il malware dispone di tutte le operazioni dell'helper come amministratore.

**Impatto concreto delle operazioni esposte.** Pur con i ricontrolli interni, l'elenco è ampio: `Remove` cancella qualunque cartella sotto `Program Files`, `Program Files (x86)`, `ProgramData` non compresa nella lista dei figli bloccati (per esempio la cartella di un antivirus di terze parti); `Quarantine` sposta via gli stessi file; `SetServiceStart` disattiva qualunque servizio non Microsoft; `DeleteTask` cancella attività; `TerminateProcess` termina processi non critici; `RemoveDefenderExclusion` e `RemoveWmiSubscription` eseguono PowerShell con input controllato (vedi H3); `RestoreQuarantined` sposta file dove dice l'indice (vedi C2). È un bypass di UAC completo, con in più un vettore di distruzione delle difese.

**Correzione.**
1. Firmare l'app e l'helper (H4) e far verificare all'helper, prima di servire la prima richiesta, che l'immagine del processo server della pipe (`GetNamedPipeServerProcessId` → `QueryFullProcessImageName`) sia `WinCleaner.exe`, nella stessa cartella dell'helper, con firma Authenticode valida dello stesso editore. Senza firma, verificare che la cartella sia sotto `Program Files` (scrivibile solo da amministratori) e che il nome sia `WinCleaner.exe`: non protegge dal lancio da una copia, ma impedisce l'uso da un eseguibile arbitrario.
2. In alternativa o in aggiunta, compilare nell'helper l'hash SHA-256 di `WinCleaner.exe` (lo script `publish.ps1` può calcolarlo e passarlo come costante o risorsa) e confrontarlo con l'immagine del server.
3. Eliminare il percorso di avvio da `C:\Windows\Temp` quando l'app non è in Program Files, oppure limitarlo a una modalità sviluppo esplicita (`--dev-helper`) che l'helper accetta solo se la cartella d'origine è dentro il profilo dell'utente attuale e che scrive un avviso chiaro nel log.
4. Ridurre la superficie: `Remove` e `Quarantine` sotto Program Files dovrebbero accettare solo cartelle che l'helper stesso riconosce come avanzi (programma non più in `Uninstall`, nessun processo in esecuzione dalla cartella) o che sono state esplicitamente confermate con un token monouso generato dall'app e mostrato nella finestra di conferma. Il log delle operazioni va scritto in una posizione che il malware non controlla (H1).

### C2. Quarantena di sistema in cartella scrivibile dagli utenti, ripristino senza controlli

**Dove**: `src/WinCleaner.Modules/Protection/Quarantine.cs:27` (`SystemFolder`), `:80-93` (`Restore`), `:107-175` (`Lock`, `Unlock`), `src/WinCleaner.Modules/Helper/HelperService.cs:198-241`.

**Problema.** La quarantena di sistema è `C:\ProgramData\WinCleaner\Quarantine`. L'helper la crea con `Directory.CreateDirectory`, che eredita la DACL di `ProgramData`: gli utenti possono creare file e cartelle, e chi crea un oggetto ne è proprietario. Se un processo a livello utente crea per primo `ProgramData\WinCleaner` (o anche solo `index.json`), ne ha il pieno controllo. L'indice è un JSON letto con `JsonSerializer` e creduto alla lettera.

`RestoreQuarantined` prende il record per id dall'indice e:
- usa `record.StoredFolder` (controllato dall'attaccante) come **radice consentita** del `SafeRemover`, quindi la sorgente può essere qualsiasi file preparato dall'attaccante;
- fa `Directory.CreateDirectory(parent)` e `OpenDirectoryPath(parent)` sulla cartella del `record.OriginalPath`, **senza alcun controllo** su dove sia e seguendo junction e collegamenti simbolici;
- sposta il file con `Rename` come amministratore.

Risultato: scrittura di un file a scelta in una posizione a scelta (per esempio una DLL in una cartella di `Program Files` che un servizio carica, o un file in `System32\Tasks`), attivata dal clic dell'utente su «Ripristina» nella pagina Quarantena, dove il record falso compare come un elemento qualsiasi. Nello scenario C1 non serve nemmeno il clic.

`Unlock` e `Lock` aggravano il quadro: lavorano per percorso (`Directory.Exists`, `SetAccessControl`, `File.SetAttributes`) su `record.StoredPath`. Se quel percorso è una junction verso `C:\Windows\System32`, `Unlock` sostituisce la DACL della destinazione con «solo il proprietario, controllo completo» e toglie l'ereditarietà: un danno al sistema e un'altra via di escalation. Lo stesso vale per `Lock` se l'attaccante, proprietario della cartella, sostituisce la sottocartella `<guid>` con una junction fra `Rename` e `Lock`.

**Correzione.**
1. L'helper crea `ProgramData\WinCleaner` e `Quarantine` con una DACL esplicita (Administrators e SYSTEM controllo completo, nessuna ereditarietà, nessun diritto per Users) e **rifiuta di usare** una cartella già esistente il cui proprietario non sia Administrators o SYSTEM o la cui DACL conceda diritti ad altri. Lo stesso per `index.json`: aprire con `FILE_FLAG_OPEN_REPARSE_POINT`, verificare proprietario e che non sia un reparse point.
2. `Restore` di sistema deve controllare che `StoredFolder` sia strettamente dentro `SystemFolder` e che `OriginalPath` sia dentro `QuarantineRoots()` (le stesse radici di `Put`), poi aprire la cartella di destinazione **componente per componente dalla radice** con `PinnedFileSystem.OpenPath` (niente reparse point), non con `OpenDirectoryPath` sul percorso intero. Niente `Directory.CreateDirectory` su percorsi presi dall'indice.
3. `Lock` e `Unlock` devono operare su handle aperti con `FILE_OPEN_REPARSE_POINT` (`SetSecurityInfo` sull'handle, non `SetNamedSecurityInfo` sul nome) e rifiutare se l'elemento è un reparse point.
4. L'app non deve leggere l'indice di sistema direttamente: aggiungere un'operazione `ListQuarantined` all'helper, oppure far firmare l'indice dall'helper (HMAC con chiave DPAPI in ambito macchina salvata in una cartella solo-amministratori) e verificarlo prima dell'uso.
5. Test da aggiungere: indice pre-creato da un utente non amministratore → rifiutato; `StoredFolder` fuori dalla quarantena → rifiutato; `OriginalPath` fuori dalle radici → rifiutato; junction nella cartella di quarantena → rifiutata.

## Trovate alte

### H1. L'helper scrive in `%LOCALAPPDATA%` da elevato

**Dove**: `src/WinCleaner.Core/OperationLog.cs:15,32-36`, `src/WinCleaner.Core/RegistryCleaner.cs:33,188-195`, `src/WinCleaner.Modules/Protection/ProtectionRegistry.cs:93-96`.

**Problema.** Log (`Logs\operations.log`, con `File.Move` e `AppendAllText`), backup `.reg` (scritti da `reg.exe export` e `Directory.CreateDirectory`) finiscono sotto `%LOCALAPPDATA%\WinCleaner`, cartella dell'utente. Quando queste scritture le fa l'helper, un processo a livello utente può sostituire `Logs` o `Backups` con una junction NTFS (nessun privilegio richiesto) o usare collegamenti dell'object manager, e ottenere la creazione o la sovrascrittura di file in cartelle di sistema come amministratore, con contenuto in parte controllato (i percorsi delle richieste finiscono nel log). È una primitiva classica di escalation.

**Correzione.** L'helper non deve scrivere nel profilo dell'utente. Due strade: (a) una cartella `ProgramData\WinCleaner\Helper` creata con DACL esplicita come in C2, aperta con `FILE_FLAG_OPEN_REPARSE_POINT` e verificata con `GetFinalPathNameByHandle`; (b) l'helper restituisce all'app il contenuto del backup e le righe di log nella risposta, e l'app li scrive nel proprio profilo con i propri diritti. La (b) è più semplice e lascia invariata l'esperienza utente. Per `reg.exe export`, far esportare in un file temporaneo nella cartella solo-amministratori e passare il testo all'app.

### H2. PowerShell e .NET elevati ereditano l'ambiente dell'utente

**Dove**: `src/WinCleaner.Modules/Performance/Maintenance.cs:97-108` (`Exec`), `src/WinCleaner.Modules/Protection/EvidenceCollection.cs`, `src/WinCleaner.Modules/Helper/HelperService.cs:279,294,301`, `src/WinCleaner.Modules/Helper/HelperClient.cs:66-68`, `src/WinCleaner.Helper/WinCleaner.Helper.csproj`.

**Problema.** Un utente può impostare variabili d'ambiente persistenti in `HKCU\Environment`, che entrano nel blocco d'ambiente anche dei processi elevati con il suo token. Tre conseguenze:
- `PSModulePath` mette per prima `Documenti\WindowsPowerShell\Modules`. I cmdlet non caricati all'avvio (`Get-MpPreference`, `Remove-MpPreference`, `Set-MpPreference`, `Get-Tpm`, `Get-CimInstance`, `Delete-DeliveryOptimizationCache`) vengono trovati per auto-caricamento del primo modulo che li esporta: un modulo piantato dall'utente viene eseguito come amministratore alla prima raccolta di prove o manutenzione.
- `COR_ENABLE_PROFILING` e `COR_PROFILER` fanno caricare una DLL arbitraria in qualunque processo .NET Framework elevato, cioè in ogni `powershell.exe` avviato dall'helper e nel bootstrap stesso. È una tecnica nota di bypass UAC.
- `DOTNET_STARTUP_HOOKS` e `CORECLR_ENABLE_PROFILING`/`CORECLR_PROFILER_PATH` fanno lo stesso con `wchelper.exe`, che è un'app .NET.

**Correzione.**
1. In `Exec` costruire un ambiente pulito per i figli: rimuovere ogni variabile che inizia con `COR_`, `CORECLR_`, `DOTNET_`, `COMPlus_`; impostare `PSModulePath` a `%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules;%ProgramFiles%\WindowsPowerShell\Modules`; impostare `PATH` a `%SystemRoot%\System32`. Vale per l'helper e anche per l'app (difesa in profondità).
2. Nel progetto dell'helper aggiungere `<StartupHookSupport>false</StartupHookSupport>`. Per il profiler non c'è interruttore in `runtimeconfig`: l'unica difesa completa è non usare .NET con JIT nell'helper (NativeAOT) oppure accettare il rischio e ridurre le occasioni in cui l'helper viene avviato. Come minimo, all'avvio l'helper può controllare che `CORECLR_ENABLE_PROFILING` non sia impostata e che i moduli caricati nel proprio processo siano solo quelli attesi, e rifiutarsi di servire richieste in caso contrario.
3. Sostituire PowerShell con chiamate dirette dove possibile, così la classe di problemi scompare: le preferenze Defender si leggono e si modificano con la classe WMI `MSFT_MpPreference` in `root\Microsoft\Windows\Defender` (metodi `Remove` e `Set`) tramite `System.Management`, già usato nel progetto; le sottoscrizioni WMI si cancellano con `ManagementObject.Delete()` su `root\subscription`; il TPM si legge da `Win32_Tpm` in `root\cimv2\Security\MicrosoftTpm`; i processi già arrivano da `Win32_Process`. Resta PowerShell solo per `Checkpoint-Computer` e `Delete-DeliveryOptimizationCache`, da eseguire con l'ambiente pulito del punto 1.
4. Il bootstrap da `C:\Windows\Temp` (C1 punto 3) è un `powershell.exe` elevato lanciato dall'app con l'ambiente che decide Windows: non è sanificabile, altro motivo per eliminarlo.

### H3. Injection PowerShell con virgolette tipografiche

**Dove**: `src/WinCleaner.Modules/Helper/HelperService.cs:276-279` (`RemoveDefenderExclusion`), `:286-293` (`RemoveWmiSubscription`).

**Problema.** Il valore viene inserito in una stringa PowerShell fra apici singoli dopo aver vietato `'`, `"`, `` ` `` e `$`. PowerShell 5.1 però accetta come apice singolo anche U+2018, U+2019, U+201A e U+201B. Un nome di esclusione o di consumer WMI che contiene `’; <comando>; ‘` esce dalla stringa ed esegue il comando come amministratore. Nello scenario normale il nome arriva dalle esclusioni effettive di Defender (che solo un amministratore può creare), quindi non c'è escalation; nello scenario C1 il nome lo sceglie l'attaccante.

**Correzione.** Non costruire mai codice PowerShell con dati. Passare il valore in una variabile d'ambiente del processo figlio (`info.Environment["WC_VALUE"] = name`) e nel comando usare `$env:WC_VALUE`; oppure, meglio, usare le API WMI del punto H2.3. Se resta una stringa, validare con una whitelist stretta (`^[A-Za-z0-9 ._:\\\-\(\)\*\%\~]+$`) oltre a `PsQuote`.

### H4. Nessuna firma del codice

**Dove**: `scripts/publish.ps1`, `installer/WinCleaner.iss`, `scripts/install.ps1`.

**Problema.** Né il setup né `WinCleaner.exe` né `wchelper.exe` sono firmati. Conseguenze: SmartScreen avvisa (il README lo riconosce); l'utente che accetta il prompt UAC vede «Editore sconosciuto» e non ha modo di distinguere il vero helper da uno rinominato; l'helper non può autenticare l'app (C1); `install.ps1` copia in Program Files, da elevato, il contenuto di una cartella estratta dallo zip nel profilo utente, dove un malware può averlo alterato fra l'estrazione e l'avvio; `Unblock-File` toglie il Mark of the Web a tutto il contenuto senza verificarne la provenienza.

**Correzione.** Un certificato di code signing (OV o EV, oppure Azure Trusted Signing, che evita la gestione della chiave) e un passo `signtool sign /fd SHA256 /tr <timestamp> /td SHA256` in `publish.ps1` per `WinCleaner.exe`, `wchelper.exe`, `wccli.exe` e le DLL del progetto, più `SignTool` nella sezione `[Setup]` di Inno per il setup e il disinstallatore. Con la firma, l'helper verifica il chiamante (C1) con `WinVerifyTrust` e il confronto del thumbprint del certificato foglia, e l'installazione da zip può verificare le firme prima di copiare.

## Trovate medie

### M1. «Dentro C:\Windows» equivale a «firmato Microsoft»

**Dove**: `src/WinCleaner.Core/Signatures.cs:47-48`, `src/WinCleaner.Modules/Performance/Startup.cs:223`.

Un file non firmato sotto `C:\Windows` viene riportato come `Signed, "Microsoft Windows"` perché molti file di sistema sono firmati tramite catalogo. Ma diverse sottocartelle di Windows sono scrivibili dagli utenti normali (`Windows\Temp`, `Windows\Tasks`, `Windows\Tracing`, `System32\spool\drivers\color`, `Registration\CRMLog`, `debug\WIA`, `System32\Tasks`). Un eseguibile lì diventa «Microsoft»: in `ProcessesCheck` salta gli avvisi su CPU sostenuta, porte di mining, nomi di processi di sistema fuori posto e DLL iniettate; in `Services()` i servizi con immagine sotto Windows non vengono nemmeno elencati; `BusyProcessWatcher` li ignora. È esattamente il nascondiglio che un malware sceglierebbe.

**Correzione.** Verificare davvero la firma a catalogo con `CryptCATAdminAcquireContext2` / `CryptCATAdminCalcHashFromFileHandle2` / `CryptCATAdminEnumCatalogFromHash` e `WinVerifyTrust` con `WTD_CHOICE_CATALOG`. Nel frattempo, considerare «Microsoft» solo i file sotto `System32`, `SysWOW64` e `WinSxS` e trattare il resto di `C:\Windows` come non firmato; non filtrare i servizi per percorso ma per firma effettiva.

### M2. DLL hijacking dell'helper nella copia in `C:\Windows\Temp`

**Dove**: `scripts/publish.ps1:30-33`, `src/WinCleaner.Modules/Helper/HelperClient.cs:110-130`, `src/WinCleaner.Modules/Helper/HelperService.cs:184` (`DeleteWiFi` → `PrivacyScanner.Scan()` → SQLite).

Il publish toglie dalla cartella dell'helper tutto tranne `wchelper.exe`; la libreria nativa `e_sqlite3.dll` resta solo accanto all'app. Quando l'helper gira dalla copia in `C:\Windows\Temp\WinCleaner-<guid>` e tocca SQLite (lo fa `DeleteWiFi` tramite `PrivacyScanner.Scan`), la ricerca della DLL passa per la `PATH` dell'utente, che contiene cartelle scrivibili (`%LOCALAPPDATA%\Microsoft\WindowsApps`): una `e_sqlite3.dll` piantata lì viene caricata come amministratore.

**Correzione.** All'avvio dell'helper chiamare `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`; togliere dall'helper le dipendenze native (per l'elenco dei profili Wi‑Fi basta `netsh wlan show profiles` o l'API WLAN, non serve lo scanner dei browser); eliminare il percorso di avvio da Temp (C1).

### M3. Lo stato di Protezione è manomettibile dal malware che dovrebbe trovare

**Dove**: `src/WinCleaner.App/Services/Infrastructure.cs:46` (`settings.json`), `src/WinCleaner.Modules/Protection/ProtectionBaseline.cs:14`, `src/WinCleaner.Modules/Protection/Signatures/SignatureScanCheck.cs:96`, `src/WinCleaner.Modules/Protection/Signatures/RuleStore.cs:31,64-68`.

Tutto sta in `%LOCALAPPDATA%\WinCleaner`: `IgnoredFindings` e `TrustedPublishers` (aggiungere il proprio editore o il proprio id nasconde l'avviso), la baseline (`last-scan.json`: nessun avviso risulterà «nuovo»), la cache delle firme, le regole YARA e `yara64.exe`, che l'app esegue. Un malware a livello utente può silenziare la Protezione o sostituire `yara64.exe` con un proprio eseguibile che gira con il nome di WinCleaner (nessuna escalation, ma copertura e persistenza).

**Correzione.** Questo limite è intrinseco al modello «stessa utenza» e va dichiarato nel README. Mitigazioni ragionevoli: memorizzare lo SHA-256 di `yara64.exe` al momento dell'aggiunta (in `settings.json` e nel log) e rifiutare di eseguirlo se cambia, mostrando un avviso di tipo Danger; includere nell'app gli hash delle release ufficiali di YARA e segnalare quando il file non corrisponde a nessuna; mostrare sempre nella pagina Protezione il numero di avvisi ignorati e di editori fidati con un clic per rivederli; non far dipendere la severità dalla baseline (lo stato «nuovo» è solo un'etichetta). Per l'esecuzione di YARA su campioni malevoli, avviarlo con un job object a bassa priorità e integrità bassa, o almeno con `CreateNoWindow` e un token ristretto.

### M4. Editore «Microsoft» per prefisso del nome

**Dove**: `src/WinCleaner.Core/Signatures.cs:10`.

`IsMicrosoft` è vero se il nome semplice dell'editore inizia con «Microsoft». Un certificato legittimo di un'azienda con un nome simile, o un certificato auto-emesso installato come radice fidata (cosa che `TrustedRootsCheck` cerca proprio perché i malware lo fanno), passa come Microsoft e spegne gli avvisi.

**Correzione.** Verificare la catena: il certificato foglia deve concatenarsi a una radice Microsoft nota (thumbprint di «Microsoft Root Certificate Authority 2010/2011» e «Microsoft Code Signing PCA 2011») oppure confrontare l'intero subject (`CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`) e l'issuer. Escludere le radici fidate installate nel negozio dell'utente.

### M5. «Apri» nell'analisi disco esegue il file

**Dove**: `src/WinCleaner.App/Pages/SpaceLensPage.xaml.cs:155-159`, `src/WinCleaner.App/Services/Infrastructure.cs:73-77`.

Il menu contestuale della mappa del disco offre «Apri» su qualunque file con `ShellExecute`: su un `.exe`, `.lnk`, `.js`, `.bat` o `.msi` sconosciuto equivale a eseguirlo. In un programma che mostra all'utente proprio i file grandi e vecchi che non riconosce, è un invito al clic sbagliato.

**Correzione.** Offrire «Apri» solo per estensioni di documento o media (elenco chiuso) e per il resto solo «Mostra in Esplora risorse»; in alternativa usare il verbo `openas` o `properties`.

## Trovate basse

- **L1. Robustezza dell'helper.** `HelperService.Remove` costruisce un dizionario per percorso e lancia se la richiesta contiene duplicati (`HelperService.cs:111-112`); `HelperJson.Deserialize` lancia su JSON malformato e termina l'helper (`Program.cs:34`). Usare `TryAdd`/`GroupBy` e un `try` attorno alla deserializzazione.
- **L2. Radici da variabili d'ambiente.** `KnownPaths.SystemDrive` e `KnownPaths.Public` vengono da `%SystemDrive%` e `%PUBLIC%` (`KnownPaths.cs:18,21`), sovrascrivibili in `HKCU\Environment`, e l'helper le usa per le radici. Derivare da `Path.GetPathRoot(KnownPaths.Windows)` e da `SHGetKnownFolderPath(FOLDERID_Public)`.
- **L3. Radici aperte seguendo i reparse point.** `OpenDirectoryPath` usa `CreateFile` senza `FILE_FLAG_OPEN_REPARSE_POINT` (`PinnedFileSystem.cs:59-75`); va bene per radici fisse e fidate, non per percorsi presi da dati (C2). Aggiungere una variante con `OBJ_DONT_REPARSE` (già definito e mai usato) per le destinazioni.
- **L4. Stringa di connessione SQLite per concatenazione.** Un percorso di profilo con `;` rompe il parsing (`SqliteDb.cs:31,44`). Usare `SqliteConnectionStringBuilder`.
- **L5. Dipendenze.** Nessun `packages.lock.json`, nessuna verifica automatica delle vulnerabilità nel publish, nessuna CI. Aggiungere `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`, `dotnet restore --locked-mode` e `dotnet list package --vulnerable --include-transitive` in `publish.ps1`; `NuGetAudit` è attivo per impostazione predefinita, ma serve che fallisca il build. La libreria di terze parti `H.NotifyIcon.WinUI` merita un controllo periodico. La nota su `SQLitePCLRaw` patchata è corretta: tenerla allineata a `Microsoft.Data.Sqlite`.
- **L6. Radici del `SafeRemover` derivate dai bersagli.** In `PrivacyCleaner.Clean` (`:33-34`) e in `StartupManager.Remove` (`:310`) le radici consentite sono le cartelle dei file da rimuovere, quindi il controllo «dentro le radici» è vuoto. I percorsi vengono dallo scanner, ma è meglio usare radici fisse (`Roots.User()`, cartella Esecuzione automatica).
- **L7. Pipe e utenti standard.** La pipe ammette solo il SID dell'utente corrente: se l'helper gira con un altro account amministratore (utente standard che inserisce credenziali admin) la connessione fallisce. È «fail closed», quindi non è una vulnerabilità, ma la funzione non è disponibile per gli utenti standard e `%LOCALAPPDATA%` dell'helper sarebbe quello dell'amministratore. Documentare o gestire.
- **L8. Durata dell'helper.** Resta vivo 30 minuti senza richieste con token amministratore. Ridurre a pochi minuti o chiuderlo alla fine di ogni operazione dell'utente riduce la finestra di C1.
- **L9. Rapporto Markdown.** Le evidenze (righe di comando, nomi) finiscono nel rapporto senza escape; chi lo incolla in un visualizzatore Markdown può vedere contenuto alterato. Racchiuderle in blocchi di codice (già fatto per `Evidence`) anche per titolo e motivo, o fare l'escape di `#`, `*`, `` ` ``.

## Cosa è fatto bene

- **File system per handle.** Apertura relativa componente per componente con `NtCreateFile` e `FILE_OPEN_REPARSE_POINT`, rifiuto di junction e collegamenti, cancellazione con semantica POSIX, rinomina senza sostituzione, Cestino scritto nel formato di Explorer. È il modo giusto di fare un cleaner e i test lo coprono.
- **Protezioni di sistema.** TrustedInstaller, Windows Resource Protection, lista dei figli bloccati, radici chiuse, voci singole con wildcard controllato, regole JSON verificate da un test che ogni percorso stia nelle radici.
- **Registro.** Elenco chiuso di posizioni, esportazione `.reg` prima di ogni modifica, valori richiesti da Windows riportati al predefinito invece che cancellati.
- **Processi esterni.** Sempre `ArgumentList`, mai una shell con stringa concatenata (eccetto H3), percorsi assoluti in `System32`, `-NoProfile -NonInteractive`.
- **Niente rete.** L'app non scarica nulla; regole e hash li porta l'utente e ne vede lo SHA-256.
- **Manifesto `asInvoker`** per l'app, una sola richiesta UAC per sessione, pipe con nome casuale, `FirstPipeInstance`, verifica dell'hash dell'helper collegato.
- **Browser.** Pulizia SQL solo a browser chiuso, copia `VACUUM INTO` riletta e messa nel Cestino, password mai lette.
- **Test.** 133 test che coprono junction, file in uso, limiti dell'helper, allow list del registro.

## Piano di rimedio consigliato, in ordine

1. **C2** (un giorno di lavoro): DACL esplicita per `ProgramData\WinCleaner`, rifiuto di cartelle con proprietario sbagliato, controlli di radice su `Restore`, apertura della destinazione per componenti, `Lock`/`Unlock` su handle, test.
2. **H3 + H2.1 + H2.2** (mezza giornata): ambiente sanificato in `Exec`, valori via `$env:`, `StartupHookSupport=false`.
3. **H1** (mezza giornata): l'helper restituisce log e backup all'app, oppure scrive in una cartella solo-amministratori.
4. **H2.3 + M2** (uno o due giorni): sostituire PowerShell con WMI per Defender e sottoscrizioni; `SetDefaultDllDirectories`; togliere SQLite dal percorso dell'helper.
5. **H4 + C1** (dipende dal certificato): firma di tutti i binari e del setup; l'helper verifica l'app chiamante; eliminazione del bootstrap da Temp; riduzione della superficie di `Remove`/`Quarantine` sotto Program Files.
6. **M1, M4, M5** (un giorno): verifica a catalogo, catena Microsoft, «Apri» solo per documenti.
7. **M3 e basse** quando c'è tempo, con il README aggiornato sui limiti del modello «stessa utenza».

## Verifiche pratiche da fare sul PC Windows dopo le correzioni

- Da un prompt **non** elevato: creare `C:\ProgramData\WinCleaner\Quarantine\index.json` con un record che punti a `C:\Windows\System32\wc-test.dll`; aprire WinCleaner, controllare che il record non compaia o che «Ripristina» fallisca e che il file non venga creato.
- Da un prompt non elevato: `mklink /J %LOCALAPPDATA%\WinCleaner\Logs C:\Windows\System32\wc-test`; eseguire un'operazione dell'helper; verificare che non nasca nulla sotto `System32`.
- Impostare `setx PSModulePath "%USERPROFILE%\Documents\WindowsPowerShell\Modules"` con un modulo `Defender` finto che scrive un file in `C:\Windows`; lanciare il controllo approfondito; il file non deve comparire.
- Impostare `setx COR_ENABLE_PROFILING 1` e `setx COR_PROFILER {guid}` con una DLL di prova; lanciare una manutenzione che usa PowerShell; la DLL non deve essere caricata nel processo elevato (controllare con Process Explorer).
- Avviare `wchelper.exe --pipe WinCleaner-test --parent <pid di un cmd>` da un programma di prova che crea la pipe: l'helper deve uscire con codice di errore senza servire richieste.
- Creare un'esclusione Defender con un nome che contiene U+2019 e rimuoverla da Protezione: il comando deve riuscire o fallire pulito, senza eseguire nulla di estraneo.
