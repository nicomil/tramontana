/*
  Regole di base di WinCleaner (licenza MIT). Euristiche generiche sui
  comportamenti tipici di dropper, miner, stealer e ransomware per Windows.
  Non sostituiscono un set di firme vero: aggiungi YARA-Forge o Elastic
  dalle Impostazioni. Richiedono yara64.exe nella cartella delle regole.
*/

private rule WinCleaner_IsBinary
{
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50 or uint32(0) == 0x464C457F
}

rule WinCleaner_PowerShell_Dropper
{
    meta:
        description = "Script PowerShell che scarica ed esegue codice nascosto"
        author = "WinCleaner"
        severity = "danger"
    strings:
        $download = /(DownloadString|DownloadFile|Invoke-WebRequest|iwr|Net\.WebClient|Start-BitsTransfer)/ ascii wide nocase
        $iex = /(IEX|Invoke-Expression)/ ascii wide nocase
        $hidden = /-w(indowstyle)?\s+hidden/ ascii wide nocase
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $b64 = "FromBase64String" ascii wide nocase
        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase
    condition:
        filesize < 2MB and not WinCleaner_IsBinary and (($download and $iex) or ($enc and $hidden) or ($b64 and $iex) or ($bypass and $hidden and $download))
}

rule WinCleaner_Crypto_Miner
{
    meta:
        description = "Stringhe tipiche dei miner di criptovalute"
        author = "WinCleaner"
        severity = "danger"
    strings:
        $stratum = "stratum+tcp://" ascii wide nocase
        $stratum2 = "stratum+ssl://" ascii wide nocase
        $xmrig = "xmrig" ascii wide nocase
        $cryptonight = "cryptonight" ascii wide nocase
        $randomx = "randomx" ascii wide nocase
        $pool = "pool.minexmr" ascii wide nocase
        $nicehash = "nicehash" ascii wide nocase
    condition:
        filesize < 50MB and 2 of them
}

rule WinCleaner_Reverse_Shell
{
    meta:
        description = "Apre una shell verso un computer remoto"
        author = "WinCleaner"
        severity = "danger"
    strings:
        $tcpclient = "System.Net.Sockets.TCPClient" ascii wide nocase
        $stream = "GetStream()" ascii wide nocase
        $cmd = "cmd.exe" ascii wide nocase
        $nc = /\bnc(at)?(\.exe)?\s+(-[a-z]*e|.*-e\s)/ ascii wide nocase
        $socket_py = "socket.socket(" ascii wide
        $dup2 = "os.dup2(" ascii wide
    condition:
        filesize < 5MB and (($tcpclient and $stream and $cmd) or $nc or ($socket_py and $dup2))
}

rule WinCleaner_Browser_Stealer
{
    meta:
        description = "Legge le password salvate dei browser e le manda via rete"
        author = "WinCleaner"
        severity = "danger"
    strings:
        $login = "\\Login Data" ascii wide nocase
        $cookies = "\\Network\\Cookies" ascii wide nocase
        $dpapi = "CryptUnprotectData" ascii wide
        $logins = "logins.json" ascii wide nocase
        $key = "\\Local State" ascii wide nocase
        $http = /https?:\/\/[a-z0-9.\-]+\/(gate|upload|api\/upload|panel|log)/ ascii wide nocase
        $telegram = "api.telegram.org/bot" ascii wide nocase
        $discord = "discord.com/api/webhooks" ascii wide nocase
    condition:
        filesize < 20MB and (($login or $cookies or $logins) and ($dpapi or $key) and ($http or $telegram or $discord))
}

rule WinCleaner_Ransomware_Prep
{
    meta:
        description = "Cancella le copie shadow o il ripristino prima di cifrare"
        author = "WinCleaner"
        severity = "danger"
    strings:
        $vss = "vssadmin" ascii wide nocase
        $shadows = "delete shadows" ascii wide nocase
        $wmic = "shadowcopy delete" ascii wide nocase
        $bcd = "recoveryenabled no" ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase
        $note = /(your files (have been|are) encrypted|decrypt(ion)? key|pay(ment)? in bitcoin)/ ascii wide nocase
    condition:
        filesize < 50MB and
        ((not WinCleaner_IsBinary and (($vss and $shadows) or $wmic or $bcd or $wbadmin or $note)) or
         (WinCleaner_IsBinary and 2 of ($shadows, $wmic, $bcd, $wbadmin, $note)))
}

rule WinCleaner_Office_Macro_Shell
{
    meta:
        description = "Macro di Office che avvia comandi all'apertura del documento"
        author = "WinCleaner"
        severity = "warning"
    strings:
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Document_Open" ascii wide nocase
        $auto3 = "Workbook_Open" ascii wide nocase
        $shell1 = "Shell(" ascii wide nocase
        $shell2 = "WScript.Shell" ascii wide nocase
        $shell3 = "CreateObject(" ascii wide nocase
        $ps = "powershell" ascii wide nocase
        $url = "http" ascii wide nocase
    condition:
        filesize < 20MB and uint16(0) != 0x5A4D and 1 of ($auto*) and 1 of ($shell*) and ($ps or $url)
}

rule WinCleaner_Persistence_Script
{
    meta:
        description = "Script che installa un avvio automatico nascosto"
        author = "WinCleaner"
        severity = "warning"
    strings:
        $run = "CurrentVersion\\Run" ascii wide nocase
        $schtasks = "schtasks" ascii wide nocase
        $create = "/create" ascii wide nocase
        $startup = "\\Startup\\" ascii wide nocase
        $hidden = /-w(indowstyle)?\s+hidden/ ascii wide nocase
        $attrib = "attrib +h" ascii wide nocase
        $copy = /copy\s+.*\\AppData\\/ ascii wide nocase
    condition:
        filesize < 2MB and not WinCleaner_IsBinary and ($run or ($schtasks and $create) or $startup) and ($hidden or $attrib or $copy)
}
