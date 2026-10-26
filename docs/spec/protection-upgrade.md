# Protezione avanzata (M7): piano di upgrade orientato alla sicurezza

> Stato: tutte le fasi sono realizzate e coperte da test (133 test xUnit sul mini PC). Differenze rispetto al piano, decise durante l'implementazione:
> - `dnYara` non include `libyara.dll`: YARA usa `yara64.exe` ufficiale messo dall'utente nella cartella delle regole, con `--scan-list` (il build Windows legge la lista come UTF-16). Il binario ufficiale non è firmato Authenticode: si confronta lo SHA-256.
> - Le regole di base escludono PE, MSI, ZIP ed ELF per dropper, macro e persistenza: nei binari legittimi quei frammenti sono comuni.
> - Il negozio radice dell'utente mostra anche le radici del computer: le CA pubbliche non vengono segnalate nemmeno lì.
> - `sfltool`-equivalente non esiste: i login item sono le voci Run, le cartelle Esecuzione automatica, le attività e i servizi già letti da `StartupManager`.
> - Le attività `\Microsoft\` con comandi tutti sotto la cartella Windows non sono segnalate; una finestra nascosta da sola è un avviso, non un pericolo.
> - Gli oggetti COM ridefiniti nel profilo con DLL firmata (installazioni per utente, es. Python) sono avvisi; `TreatAs` conta solo verso librerie fuori dai programmi.
> - La quarantena blocca i figli prima dei genitori (il contrario per sbloccare) e scrive lo stream `Zone.Identifier` prima dell'attributo nascosto.

Gemello del piano di MacCleaner (`../../maccleaner/docs/spec/protection-upgrade.md`), riscritto per Windows. Obiettivo: fare meglio di "apro Gestione attività, guardo i processi sospetti, lancio CCleaner". Le quattro domande sono le stesse:

1. **Cosa si avvia da solo** su questo PC, e da quando?
2. **Cosa sta girando adesso**, e chi consuma CPU, RAM, rete e disco in modo anomalo?
3. **C'è traccia di malware** (Defender, hash noti, driver vulnerabili, regole YARA, tecniche di persistenza tipiche)?
4. **Le difese di Windows sono accese** e configurate bene?

Ma Windows parte da una posizione peggiore, e il piano lo tiene presente:

- **Molti più posti dove nascondersi.** Oltre a Run, cartelle Esecuzione automatica, attività e servizi ci sono Winlogon, IFEO, AppInit_DLLs, sottoscrizioni WMI, BITS, COM hijacking, LSA, estensioni della shell, Active Setup, provider di stampa, netsh, profili PowerShell, componenti aggiuntivi di Office. Il malware per Windows li usa tutti.
- **Il malware è spesso "legittimo".** Bundleware, adware, estensioni forzate dai criteri del browser (`ExtensionInstallForcelist`), "ottimizzatori" e falsi antivirus arrivano firmati e con un disinstallatore. Il criterio non può essere solo "non firmato".
- **Strumenti di sistema usati contro l'utente** (LOLBins): `powershell -enc`, `mshta`, `rundll32`, `regsvr32 /i:http`, `certutil -decode`, `bitsadmin`, `wscript`, `msiexec /q` da URL. La riga di comando conta quanto il file.
- **Defender viene manomesso** prima di tutto: esclusioni aggiunte, protezione in tempo reale spenta, `DisableAntiSpyware` da criterio, anti-manomissione spenta. Vanno controllati sempre, per primi.
- **Impostazioni predefinite deboli**: estensioni dei file nascoste (`fattura.pdf.exe`), AutoPlay, SMBv1 sui PC vecchi, WDigest, nessun BitLocker, utente amministratore senza password separata.
- **Si può fare di più senza privilegi**, ma le cose importanti (esclusioni di Defender, sottoscrizioni WMI, processi di altri utenti, moduli caricati, log di sicurezza) servono l'helper elevato. Una sola richiesta UAC per sessione, come oggi.

Filosofia invariata: niente preselezioni sugli elementi a rischio, ogni segnalazione spiega il motivo e mostra l'evidenza, nessuna rimozione senza conferma, operazioni di sistema solo tramite l'insieme chiuso di `wchelper`.

## Stato attuale (M4/M5)

`ProtectionScanner` (statico, `src/WinCleaner.Modules/Protection/`) copre:

| Area | Cosa c'è | Cosa manca |
|---|---|---|
| Difese | antivirus da Security Center, protezione in tempo reale, età analisi, anti-manomissione, firewall per profilo, UAC, SmartScreen, Avvio protetto, Desktop remoto | esclusioni di Defender, Defender spento da criterio, ASR, LSASS PPL, Credential Guard, WDigest, BitLocker, aggiornamenti automatici, estensioni nascoste, AutoPlay, SMBv1, WinRM, Registro remoto, account (admin, Guest, nascosti, login automatico con password in chiaro), criteri di esecuzione PowerShell, Windows Script Host, macro di Office |
| Avvio | Run/RunOnce, cartelle Esecuzione automatica, attività fuori da `\Microsoft\`, servizi non Microsoft; script host, cartelle temporanee, firma, nomi che imitano Microsoft | Winlogon (Shell, Userinit, Notify), IFEO (Debugger, accessibilità dirottata), AppInit_DLLs, AppCert, sottoscrizioni WMI, lavori BITS, COM hijacking in HKCU, Active Setup, LSA packages, estensioni della shell e BHO, provider di stampa, netsh helper, profili PowerShell, cartella Startup di Office/XLSTART, attività nascoste (TaskCache senza SD), servizi `svchost -k` con `ServiceDll` non firmata, driver non firmati o vulnerabili |
| Browser | estensioni Chromium con origine dalle preferenze | estensioni forzate dai criteri (`ExtensionInstallForcelist`, `3rdparty`), homepage, pagine di avvio e motore di ricerca, Firefox, Edge policies, `DefaultSearchProviderSearchURL` da criterio |
| Rete | hosts, proxy, PAC | DNS per interfaccia, Winsock LSP/NameSpace, regole del firewall in entrata per programmi non firmati, porte in ascolto, certificati radice aggiunti |
| Processi | nessun controllo | inventario con firma, riga di comando, padre, utente; CPU, RAM, I/O, rete per processo; connessioni; moduli caricati non firmati; nomi di sistema in posizioni sbagliate |
| Firme | analisi rapida Defender | analisi Defender mirata sui file sospetti, cronologia delle minacce, hash MalwareBazaar, elenco LOLDrivers, YARA opzionale |
| Storico | ignorati in Settings | baseline e "nuovo dall'ultimo controllo", rapporto esportabile |
| Test | script e cartelle temporanee all'avvio, origine estensioni | fixture per registro, WMI e processi tramite interfacce iniettabili |

## Principi di progettazione

- **Ogni controllo è un'unità** (`IProtectionCheck`): nome, categoria, requisito (nessuno / amministratore) e `Run(CheckContext)`. Lo scanner è la somma dei controlli e li esegue in parallelo con timeout.
- **`Finding` esteso**: categoria, gravità, titolo, percorso o chiave di registro, motivi, *evidenze* grezze (valore del registro, riga di comando, riga di `netstat`), azione consigliata (disattiva avvio, Cestino, quarantena, elimina valore, apri impostazioni, termina processo, analizza con Defender), `FirstSeen`, `IsNew`, editore della firma.
- **Baseline e differenza**: istantanea JSON in `%LOCALAPPDATA%\WinCleaner\Protection\last-scan.json`; "nuovo dall'ultimo controllo" è il segnale più utile sul PC che "fa sempre casini".
- **Tutto ciò che si legge è dato ostile**: valori del registro, righe di comando, manifest, script, output di comandi, log. Parsati con limiti, mai eseguiti, mai interpolati in una riga di comando.
- **Privilegi minimi**: la scansione standard non chiede UAC. Il "Controllo approfondito" usa una sola operazione dell'helper di sola lettura (`CollectSystemEvidence`) con un elenco fisso di letture, senza argomenti dall'esterno. Le azioni privilegiate sono operazioni dedicate, tipizzate, ricontrollate dall'helper.
- **Falsi positivi gestiti**: "Ignora", editori fidati (nome del soggetto del certificato), allowlist di strumenti di sviluppo, livello "Informazioni" nascosto di default.
- **Testabilità**: `IRegistryReader`, `ICommandRunner`, `ISignatureEvaluator`, `IProcessSource`, `IWmiSource` con implementazioni finte nei test. I test girano su Windows (`scripts/remote.sh dotnet test …`) ma non dipendono dallo stato del PC.

## Fasi

### Fase 0: fondamenta e test

- `IProtectionCheck`, `CheckContext` (home, registro, comandi, firme, processi, WMI, evidenza di sistema, editori fidati), `Finding` esteso. `ProtectionScanner.Scan` resta come facciata.
- `ProtectionBaseline` con `FirstSeen`/`IsNew`, dimenticando gli id assenti da 90 giorni.
- `ProtectionReport` (Markdown) con difese, riepilogo, finding per categoria con evidenze, processi più attivi.
- Spostare i controlli esistenti nelle unità: `DefencesCheck`, `StartupCheck`, `BrowserExtensionsCheck`, `NetworkConfigCheck`, `DevicesCheck`. Fixture per ognuno (registro finto con chiavi Run, attività finte, `Preferences` di Chromium in cartella temporanea).
- `wccli protection` stampa categoria, evidenze e novità; `wccli posture`, `wccli processes`, `wccli signatures` nelle fasi seguenti.

### Fase 1: postura delle difese (costo basso, valore alto)

Tutti senza UAC salvo dove indicato. Ognuno con link `ms-settings:` o `windowsdefender:`.

| Controllo | Fonte | Segnalazione |
|---|---|---|
| Defender spento da criterio | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` `DisableAntiSpyware`, `DisableRealtimeMonitoring` | danger: è il primo gesto del malware |
| Esclusioni di Defender | `MSFT_MpPreference` `ExclusionPath/Process/Extension` (admin, nell'evidenza di sistema) | warning per ogni esclusione; danger se copre `C:\`, `%TEMP%`, `Users`, `.exe` |
| Minacce recenti di Defender | `MSFT_MpThreatDetection` (ultimi 30 giorni) e log `Microsoft-Windows-Windows Defender/Operational` eventi 1116/1117/1015 | danger con nome, file e azione presa |
| Regole ASR, protezione rete, cartelle controllate | `MSFT_MpPreference` `AttackSurfaceReductionRules_*`, `EnableNetworkProtection`, `EnableControlledFolderAccess` | info "consigliato attivare" |
| LSASS protetto, Credential Guard, WDigest | `HKLM\SYSTEM\...\Lsa` `RunAsPPL`; `DeviceGuard` `SecurityServicesRunning`; `WDigest\UseLogonCredential` = 1 | WDigest = 1 → danger (password in memoria in chiaro) |
| BitLocker | `Win32_EncryptableVolume` (admin) o `manage-bde -status` | disco di sistema non cifrato → warning |
| Aggiornamenti | `HKLM\...\WindowsUpdate\Auto Update` `NoAutoUpdate`, `AUOptions`; servizio `wuauserv` disattivato; ultimo aggiornamento da `Win32_QuickFixEngineering` o `LastSuccessTime` | disattivato → danger; nessun aggiornamento da 60 giorni → warning |
| Estensioni dei file nascoste, file nascosti | `HKCU\...\Explorer\Advanced` `HideFileExt` = 1, `Hidden` ≠ 1 | warning "fattura.pdf.exe sembra un PDF", con azione "Mostra le estensioni" (scrittura in HKCU, reversibile) |
| AutoPlay/AutoRun | `NoDriveTypeAutoRun` ≠ 0xFF, `HKCU\...\AutoplayHandlers` `DisableAutoplay` | info |
| SMBv1, LLMNR, NetBIOS | `Win32_OptionalFeature` SMB1Protocol, `HKLM\SOFTWARE\Policies\...\DNSClient` `EnableMulticast` | SMBv1 → danger (WannaCry) |
| WinRM, Registro remoto, Assistenza remota, RDP senza NLA | servizi `WinRM`, `RemoteRegistry`; `fAllowToGetHelp`; `UserAuthentication` = 0 | warning |
| Account | `Win32_UserAccount` locali: amministratori (`net localgroup`), Guest attivo, account nascosti (`SpecialAccounts\UserList`), password che non scadono, account creati di recente | admin extra → info; nascosti → danger; Guest → warning |
| Login automatico | `Winlogon` `AutoAdminLogon` = 1, `DefaultPassword` presente | password in chiaro nel registro → danger |
| PowerShell e script | `ExecutionPolicy` Unrestricted/Bypass da criterio; Windows Script Host abilitato (`Settings\Enabled`); registrazione script spenta | info/warning |
| Macro di Office | `HKCU\Software\Microsoft\Office\<ver>\<app>\Security` `VBAWarnings` = 1 | danger (macro senza avviso) |
| Attestazioni UEFI | Secure Boot (già), TPM presente e pronto (`Win32_Tpm`) | info |
| Gatekeeper equivalente | SmartScreen (già), `EnableSmartScreen` da criterio, SmartScreen di Edge | — |

Azioni nuove dell'helper: `EnableDefenderRealtime`, `RemoveDefenderExclusion(path)` (solo quelle trovate dall'helper stesso), `EnableWindowsUpdate`. Nessuna modifica a criteri di gruppo di dominio: se il PC è in un dominio, i criteri sono segnalati come "gestiti" e basta.

### Fase 2: persistenza completa

Nuove unità, ognuna con la stessa valutazione di firma, posizione e riga di comando (`StartupAssessor`, estratto da `Assess`):

- **Winlogon**: `Shell` ≠ `explorer.exe`, `Userinit` ≠ `userinit.exe,`, `Notify`, `Taskman`, `VmApplet`; `HKCU` versioni. Qualsiasi valore extra → danger.
- **IFEO**: `Image File Execution Options\<exe>\Debugger` presente → danger (classico `sethc.exe`/`utilman.exe` → backdoor della schermata di blocco); `GlobalFlag`/`SilentProcessExit` `MonitorProcess` → danger.
- **AppInit_DLLs, AppCertDLLs, LoadAppInit_DLLs**: qualsiasi valore → danger; mostra le DLL con firma.
- **Sottoscrizioni WMI** (`root\subscription`: `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `__FilterToConsumerBinding`), lettura admin: qualsiasi consumer non Microsoft → danger con la query e il comando.
- **Lavori BITS** (`bitsadmin /list /allusers` nell'evidenza di sistema, o API `IBackgroundCopyManager`): lavori con `NotifyCmdLine` o verso URL grezzi → danger.
- **COM hijacking**: CLSID in `HKCU\Software\Classes\CLSID\*\InprocServer32` che esistono anche in `HKLM` con un percorso diverso → danger; `TreatAs`; `ScriptletURL`.
- **Active Setup** (`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`) con `StubPath` non Microsoft → warning.
- **LSA**: `Authentication Packages`, `Notification Packages`, `Security Packages` con DLL non di sistema → danger.
- **Estensioni della shell e BHO**: `ShellExecuteHooks`, `ShellServiceObjectDelayLoad`, `Browser Helper Objects`, `ContextMenuHandlers`, `ShellIconOverlayIdentifiers` con DLL non firmate o fuori da Program Files → warning.
- **Provider**: `Print\Monitors`, `Print\Providers`, `NetSh` helper DLL, `Winsock` `Catalog_Entries` (LSP) e `NameSpace_Catalog5` non di sistema → danger.
- **Profili PowerShell** (`$PROFILE` per host e `AllUsers`), `Microsoft.PowerShell_profile.ps1`: contenuto con download, `-enc`, `IEX`, `Invoke-Expression`, `FromBase64String`, `DownloadString`, `Start-Process -WindowStyle Hidden` → danger; modificato di recente → info.
- **Office**: `XLSTART`, `STARTUP` di Word, `Templates\Normal.dotm` modificato di recente, componenti aggiuntivi COM (`HKCU\Software\Microsoft\Office\<app>\Addins`) non firmati → warning.
- **Attività nascoste**: chiavi in `Schedule\TaskCache\Tasks` senza la corrispondente `Tree` o con `SD` assente (tecnica dei rootkit "HAFNIUM") → danger. Attività con azioni LOLBin, trigger ad ogni accesso, autore vuoto, XML in `C:\Windows\System32\Tasks` modificato di recente.
- **Servizi**: `ServiceDll` di `svchost -k` non firmata o fuori da System32 → danger; servizi con `ImagePath` senza virgolette e spazi (unquoted path) → warning; eseguibile in cartelle utente → warning; driver (`Type` 1/2) non firmati → danger; driver presenti nell'elenco LOLDrivers (Fase 5) → danger.
- **Debug e strumenti di accessibilità sostituiti**: hash di `sethc.exe`, `utilman.exe`, `osk.exe`, `narrator.exe`, `magnify.exe` diverso dal catalogo (non firmati Microsoft) → danger.
- **Programmi installati di recente** (`Uninstall` con `InstallDate` ultimi 30 giorni): editore vuoto o non firmato, nome che richiama "cleaner/optimizer/driver updater/PC speed", con voce di avvio automatico → warning "possibile programma indesiderato"; evidenza: cartella, editore, disinstallatore, MOTW dell'installer se ancora nei Download (`Zone.Identifier` con `HostUrl`).
- **Browser**: estensioni forzate da criterio (`HKLM/HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist`, `Microsoft\Edge\...`, `BraveSoftware`), `DefaultSearchProviderSearchURL`, `HomepageLocation`, `RestoreOnStartupURLs` da criterio su PC non in dominio → danger (è il trucco standard dell'adware); `Preferences` Chromium (`homepage`, `session.startup_urls`, `default_search_provider_data`); Firefox `prefs.js`/`user.js` (`browser.startup.homepage`, `keyword.enabled`, `extensions.autoDisableScopes`), `distribution\policies.json`, add-on fuori da AMO; Edge `Secure Preferences`.
- **Certificati radice**: `X509Store(StoreName.Root, LocalMachine/CurrentUser)` + `AuthRoot`: radici non presenti nell'elenco Microsoft (`certutil -generateSSTFromWU` opzionale) e aggiunte dopo l'installazione di Windows → danger (intercettazione HTTPS, tipico di adware e "antivirus" gratuiti).
- **Rete**: DNS per interfaccia (`Win32_NetworkAdapterConfiguration`) non del router né noti → warning; regole del firewall in entrata "allow" per programmi non firmati o in cartelle utente (`INetFwRules`) → warning; `netsh winhttp show proxy`; porte in ascolto da processi non Microsoft (Fase 3).

### Fase 3: processi e risorse (la "Gestione attività" con giudizio)

Nuova pagina **Attività**, campionata ogni 2 secondi finché è aperta, più tre campioni nella scansione.

- **Inventario**: `Process.GetProcesses` più `NtQuerySystemInformation(SystemProcessInformation)` per padre e tempi; percorso con `QueryFullProcessImageName`; riga di comando da `Win32_Process` (`CommandLine`) o `NtQueryInformationProcess(PEB)`; utente da token. Senza admin si vedono percorsi e righe di comando dei propri processi; con l'evidenza di sistema, di tutti.
- **Risorse**: CPU da `GetProcessTimes` (delta), memoria `PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`, disco `GetProcessIoCounters` (delta), rete per processo dal contatore ETW `Microsoft-Windows-Kernel-Network` o, più semplice, da `GetExtendedTcpTable`/`GetExtendedUdpTable` (connessioni, porte in ascolto, PID) più byte per processo da `GetPerTcpConnectionEStats` quando disponibile.
- **Euristiche**:
  - non firmato in `%TEMP%`, `%APPDATA%` radice, `ProgramData` radice, `Public`, `$Recycle.Bin`, Download → warning/danger;
  - nome di sistema (`svchost`, `lsass`, `csrss`, `winlogon`, `explorer`, `RuntimeBroker`, `dllhost`…) fuori da `System32`/`SysWOW64`, o `svchost` con padre diverso da `services.exe`, `lsass` duplicato → danger;
  - eseguibile cancellato mentre gira → danger;
  - riga di comando con `-enc`, `-w hidden`, `IEX`, `DownloadString`, `mshta http`, `rundll32 javascript:`, `regsvr32 /i:http`, `certutil -urlcache`, `bitsadmin /transfer` → danger;
  - processo figlio di Office, browser o `wscript` che avvia `powershell`/`cmd`/`mshta` → danger;
  - CPU ≥ 80% per tre campioni da processo non Microsoft → warning; con connessioni a porte di mining (3333, 4444, 5555, 7777, 14444) o `stratum` → danger;
  - in ascolto su `0.0.0.0` da processo non Microsoft non firmato → warning; connessioni a IP grezzi su porte insolite (4444, 1337, 6667, 8080 verso IP residenziali…) → warning;
  - **moduli caricati** (`EnumProcessModulesEx`, admin per gli altri utenti): DLL non firmate in `%TEMP%` o `%APPDATA%` dentro processi firmati (`explorer.exe`, browser) → danger (iniezione).
- **Azioni**: "Mostra nel Finder" → "Mostra in Esplora risorse", "Vai all'elemento di avvio", "Termina" (proprio utente; con l'helper per gli altri, `TerminateProcess(pid, percorso atteso)` che ricontrolla il percorso prima di uccidere), "Termina e quarantena", "Analizza con Defender" (`MpCmdRun -Scan -ScanType 3 -File <path>`).
- **Icona nell'area di notifica**: avviso quando un processo non Microsoft satura un core per oltre un minuto o apre una porta in ascolto.

### Fase 4: azioni, quarantena, rapporto, automazione

- **Quarantena** come alternativa al Cestino: `%LOCALAPPDATA%\WinCleaner\Quarantine\<id>\` con `manifest.json`, spostamento tramite `PinnedFileSystem` (rinomina dell'handle, mai per percorso), DACL ridotta al solo utente in lettura (nessun `Execute`), attributi `Hidden`, stream `Zone.Identifier` con `ZoneId=3` così SmartScreen blocca anche una copia. File di sistema: operazione `Quarantine` dell'helper verso `C:\ProgramData\WinCleaner\Quarantine` con DACL amministratori/SYSTEM. `RestoreQuarantined`, `DeleteQuarantined`. Pagina "Quarantena".
- **Sequenza di rimozione sicura**: termina il processo (e i figli) → disattiva o elimina l'elemento di avvio (attività, servizio, Run, WMI) → verifica che non sia ricomparso → quarantena del file → nuova scansione. Si ferma al primo passo che fallisce.
- **Rimozioni di registro mirate** (helper, con backup `.reg`): `RestoreWinlogonDefaults`, `RemoveIfeoDebugger(exe)`, `ClearAppInitDlls`, `RemoveWmiSubscription(nome)`, `RemoveComHijack(clsid)`, `RemoveExtensionForceList(id)`, `RemoveDefenderExclusion`. Ogni operazione ha la sua allowlist esatta: l'elenco "mai la chiave Microsoft" resta per tutto il resto.
- **Analisi Defender mirata**: dopo la scansione, i file `danger`/`warning` vengono passati a `MpCmdRun -Scan -ScanType 3 -File` (gira come utente); l'esito finisce nelle evidenze. Cronologia minacce in Protezione.
- **Rapporto** Markdown esportabile; **Controllo integrità** mostra pericoli e "nuovi"; **analisi pianificata** esegue anche Protezione e notifica solo i pericoli nuovi.
- **Correzioni con un clic** reversibili (HKCU): mostra estensioni, disattiva AutoPlay, macro con avviso.

### Fase 5: firme aperte

- **LOLDrivers** (`loldrivers.io`, JSON pubblico, licenza aperta): hash SHA-256 dei driver vulnerabili o malevoli; confrontati con i driver installati (`DriverStore`, `System32\drivers`) e caricati. Scaricato dall'utente dalle Impostazioni, con SHA-256 mostrato. È la fonte più preziosa su Windows: i "BYOVD" spengono Defender.
- **MalwareBazaar** CSV (tag `exe`, `dll`, `msi`): hash dei file candidati (eseguibili e script in Download, Desktop, `%TEMP%`, `%APPDATA%`, `ProgramData`, cartelle di avvio, programmi degli elementi di avvio, moduli caricati).
- **YARA**: `dnYara` (NuGet, include `libyara` nativa per x64; per ARM64 compilare `libyara` come progetto C in `src/WinCleaner.Yara` con lo stesso approccio di MacCleaner) oppure, come ripiego, `yara64.exe` dalla release ufficiale copiata accanto all'app. Regole: YARA-Forge "core" filtrato Windows, regole di base scritte da noi (dropper PowerShell, miner, reverse shell, stealer di browser). Cache per `percorso+dimensione+data`. Ambito limitato ai posti dove il malware vive; limite 50 MB; mai i file solo-cloud di OneDrive.
- **Defender resta l'antivirus**: YARA e hash sono un secondo parere, con la quarantena come azione.

## Requisiti di accesso per controllo

| Richiede | Controlli |
|---|---|
| Niente | Run/avvio, attività, servizi, Winlogon, IFEO, AppInit, Active Setup, LSA, shell, provider, profili PowerShell, Office, browser e criteri, certificati, hosts/proxy/DNS, regole firewall, programmi installati, postura (quasi tutta), processi e connessioni dell'utente, YARA e hash sui file dell'utente, Defender quick scan e scan mirato |
| Amministratore (una richiesta UAC, `CollectSystemEvidence` di sola lettura) | esclusioni e preferenze di Defender, sottoscrizioni WMI, lavori BITS di tutti, BitLocker, TPM, attività e profili di altri utenti, processi/moduli/righe di comando di altri utenti, log di sicurezza, hash dei driver in `System32\drivers` |

## Struttura del codice

```
src/WinCleaner.Modules/Protection/
  IProtectionCheck.cs        interfaccia, Finding esteso, categorie, CheckContext, interfacce iniettabili
  ProtectionScanner.cs       orchestrazione (facciata esistente)
  ProtectionBaseline.cs
  ProtectionReport.cs
  StartupAssessor.cs         firma, posizione, riga di comando (estratto da Assess)
  Checks/
    DefencesCheck.cs           (esistente, esteso)
    DefenderCheck.cs           esclusioni, criteri, minacce, ASR
    PostureCheck.cs            credenziali, aggiornamenti, Explorer, AutoPlay, SMB, remoto, account, Office, PowerShell
    StartupCheck.cs            Run, cartelle, attività, servizi (esistente)
    WinlogonIfeoCheck.cs       Winlogon, IFEO, AppInit, AppCert, accessibilità
    WmiBitsCheck.cs
    ComHijackCheck.cs
    ShellAndProvidersCheck.cs  Active Setup, LSA, shell, BHO, print, netsh, Winsock
    ScriptsAndOfficeCheck.cs   profili PowerShell, XLSTART, add-in
    HiddenTasksCheck.cs
    ServicesAndDriversCheck.cs
    RecentProgramsCheck.cs
    BrowserExtensionsCheck.cs  (esistente) + criteri forzati, Firefox
    BrowserHijackCheck.cs
    TrustedRootsCheck.cs
    NetworkConfigCheck.cs      hosts, proxy, DNS, regole firewall (esistente, esteso)
    DevicesCheck.cs            (esistente)
    SignatureScanCheck.cs      LOLDrivers, hash, YARA
  Processes/
    ProcessInventory.cs        NtQuerySystemInformation, percorsi, righe di comando, utenti
    ResourceSampler.cs         tempi, memoria, I/O, tabelle TCP/UDP
    LoadedModules.cs
    ProcessesCheck.cs
  Quarantine.cs
  RuleStore.cs                 regole YARA, hash, LOLDrivers con SHA-256
src/WinCleaner.Helper/         nuove operazioni: CollectSystemEvidence, Quarantine, RestoreQuarantined, DeleteQuarantined,
                               TerminateProcess, RemoveDefenderExclusion, EnableDefenderRealtime, RestoreWinlogonDefaults,
                               RemoveIfeoDebugger, ClearAppInitDlls, RemoveWmiSubscription, RemoveComHijack, RemoveExtensionForceList
src/WinCleaner.App/Pages/      ProtectionPage (gruppi, "nuovo", evidenze, quarantena, rapporto), ActivityPage, QuarantinePage, SettingsPage (regole)
tests/WinCleaner.Tests/Protection/  una fixture per check: registro finto, output campione di WMI/netsh/bitsadmin, processi finti
```

## Cosa resta fuori (per scelta)

- Un driver kernel o un minifilter (monitor in tempo reale del file system): serve una firma EV e l'attestazione Microsoft.
- Scansione completa del disco con YARA: lenta e piena di falsi positivi; Defender la fa già.
- Database proprietari: nessuna chiave VirusTotal; "cerca l'hash su VirusTotal" apre il browser.
- Modifica dei criteri di gruppo di un PC in dominio: solo segnalazione.
- Aggiornamento dei driver (già escluso dal progetto).

## Verifica

- Test unitari per ogni check con fixture e letture finte: chiavi Winlogon alterate, IFEO con `Debugger`, sottoscrizione WMI campione, CLSID dirottato, attività senza SD, servizio con `ServiceDll` in `%APPDATA%`, criterio `ExtensionInstallForcelist`, esclusione Defender su `C:\`, profilo PowerShell con `IEX (New-Object Net.WebClient).DownloadString`.
- Test del campionatore sul processo di test e su un `cmd.exe` copiato in `%TEMP%\.x\` con nome `svchost.exe` (deve risultare "nome di sistema fuori da System32, cartella temporanea").
- Test di `PinnedFileSystem` per la quarantena con junction scambiata, come già fatto per Cestino ed eliminazione; test della DACL ridotta e dello stream `Zone.Identifier`.
- Prova manuale sul mini PC con un "malware finto": valore Run verso uno script in `%TEMP%`, attività pianificata con `powershell -enc`, sottoscrizione WMI di test, `Debugger` su `sethc.exe`, criterio di estensione forzata, esclusione Defender su `%TEMP%`. Tutti `danger` con il motivo giusto; tutti spariti dopo le azioni; Defender non deve essere disturbato (il malware finto non deve essere eseguibile reale).
- `wccli protection|posture|processes|signatures` per confrontare più PC senza interfaccia e per il PC del papà via SSH.

## Stima e ordine

| Fase | Dimensione | Note |
|---|---|---|
| 0 Fondamenta | media | prerequisito; refactoring dello scanner statico |
| 1 Postura e Defender | media | su Windows è la fase di maggior valore |
| 2 Persistenza | grande | molte unità piccole, tutte sul registro |
| 3 Processi | grande | nuova pagina, P/Invoke, moduli caricati |
| 4 Azioni e quarantena | media-grande | tocca l'helper e la DACL |
| 5 Firme | media | LOLDrivers e hash subito; YARA dipende da dnYara/ARM64 |

Ordine consigliato: 0 → 1 → 2 → 3 → 4 → 5, ogni fase rilasciabile e provata sul mini PC prima della successiva.
