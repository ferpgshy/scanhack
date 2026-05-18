#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecurityAudit.ps1 v3.0 — Relatório de comprometimento com baixo índice de falsos positivos
.NOTES
    Execute como Administrador no PowerShell 5.1+
#>

# Set-StrictMode removido: conflita com $ErrorActionPreference=SilentlyContinue
# causando falha no here-string do $HTML quando colecoes retornam objeto unico
$ErrorActionPreference = 'SilentlyContinue'

# Fallback para $PSScriptRoot (compatibilidade com diferentes formas de invocar)
$Script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path $MyInvocation.MyCommand.Path -Parent } else { (Get-Location).Path }

# ─────────────────────────────────────────────
#  CONFIGURAÇÃO
# ─────────────────────────────────────────────
$Script:StartTime  = Get-Date
$Script:Timestamp  = $Script:StartTime.ToString('HH-mm')
$Script:DateFolder = $Script:StartTime.ToString('yyyy-MM-dd')
$Script:ReportsDir = Join-Path $Script:ScriptDir "reports\$Script:DateFolder"
Write-Host "  Pasta de relatorios: $Script:ReportsDir" -ForegroundColor DarkGray
if (-not (Test-Path $Script:ReportsDir)) { New-Item -ItemType Directory -Path $Script:ReportsDir -Force | Out-Null }
$Script:ReportHTML = Join-Path $Script:ReportsDir "audit_$($Script:Timestamp).html"
$Script:ReportTXT  = Join-Path $Script:ReportsDir "audit_$($Script:Timestamp).txt"
$Script:Findings   = [System.Collections.Generic.List[hashtable]]::new()
$Script:RiskScore  = 0

# ── Interface Web — progresso em tempo real (async, sem runspace) ───
$Script:CurrentStep     = 0
$Script:CurrentStepName = 'Iniciando...'
$Script:Duration_       = ''
$Script:ReportReady     = $false
$Script:Listener        = $null
$Script:Port            = $null
$Script:AsyncResult     = $null
$Script:ReportServed    = $false

$Script:ProgressPage = '<html><body>Interface nao encontrada</body></html>'
$_ppPath = Join-Path $Script:ScriptDir 'progress.html'
if (Test-Path $_ppPath) {
    $Script:ProgressPage = [System.IO.File]::ReadAllText($_ppPath, [System.Text.Encoding]::UTF8)
}

for ($p_ = 8751; $p_ -le 8770; $p_++) {
    try {
        $l_ = [System.Net.HttpListener]::new()
        $l_.Prefixes.Add('http://localhost:' + $p_ + '/')
        $l_.Start()
        $Script:Listener = $l_; $Script:Port = $p_; break
    } catch { }
}

function Invoke-WebServer {
    if (-not $Script:Listener -or -not $Script:AsyncResult -or -not $Script:AsyncResult.IsCompleted) { return }
    try {
        $ctx_ = $Script:Listener.EndGetContext($Script:AsyncResult)
        $enc_ = [System.Text.Encoding]::UTF8
        $res_ = $ctx_.Response
        switch ($ctx_.Request.Url.AbsolutePath) {
            '/' {
                $b_ = $enc_.GetBytes($Script:ProgressPage)
                $res_.ContentType = 'text/html; charset=utf-8'
                $res_.ContentLength64 = $b_.Length
                $res_.OutputStream.Write($b_, 0, $b_.Length)
            }
            '/api/status' {
                $j_ = [PSCustomObject]@{
                    stepIndex    = [int]$Script:CurrentStep
                    totalSteps   = 9
                    stepName     = [string]$Script:CurrentStepName
                    done         = [bool]$Script:ReportReady
                    iocs         = [int]$Script:Findings.Count
                    duration     = [string]$Script:Duration_
                    computerName = $env:COMPUTERNAME
                    startTime    = $Script:StartTime.ToString('dd/MM/yyyy HH:mm:ss')
                }
                $b_ = $enc_.GetBytes(($j_ | ConvertTo-Json -Compress))
                $res_.ContentType = 'application/json'
                $res_.ContentLength64 = $b_.Length
                $res_.OutputStream.Write($b_, 0, $b_.Length)
            }
            '/report' {
                if ($Script:ReportReady -and (Test-Path $Script:ReportHTML)) {
                    $b_ = [System.IO.File]::ReadAllBytes($Script:ReportHTML)
                    $res_.ContentType = 'text/html; charset=utf-8'
                    $res_.ContentLength64 = $b_.Length
                    $res_.OutputStream.Write($b_, 0, $b_.Length)
                    $Script:ReportServed = $true   # browser recebeu o relatorio
                } else { $res_.Redirect('/') }
            }
            default {
                $res_.StatusCode = 404
                $b_ = $enc_.GetBytes('Not found')
                $res_.OutputStream.Write($b_, 0, $b_.Length)
            }
        }
        $res_.OutputStream.Close()
    } catch { try { $ctx_.Response.OutputStream.Close() } catch {} }
    # Fila o proximo request async
    try { $Script:AsyncResult = $Script:Listener.BeginGetContext($null, $null) } catch {}
}

if ($Script:Listener) {
    try { $Script:AsyncResult = $Script:Listener.BeginGetContext($null, $null) } catch {}
    Start-Process ('http://localhost:' + $Script:Port + '/')
    Write-Host ('  Interface web: http://localhost:' + $Script:Port) -ForegroundColor Cyan
} else {
    Write-Host '  [AVISO] Nao foi possivel iniciar servidor web de progresso' -ForegroundColor Yellow
}

# ── Whitelist de processos do sistema ─────────
$KnownProcesses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    'svchost','lsass','csrss','winlogon','services','smss','wininit','explorer',
    'dwm','taskhostw','sihost','ctfmon','conhost','dllhost','SearchIndexer',
    'spoolsv','WmiPrvSE','RuntimeBroker','ShellExperienceHost','fontdrvhost',
    'audiodg','SearchHost','System','Idle','Registry','MemCompression','LsaIso',
    'SgrmBroker','AgentService','StartMenuExperienceHost','SecurityHealthService',
    'MsMpEng','NisSrv','TextInputHost','UserOOBEBroker','ApplicationFrameHost',
    'backgroundTaskHost','WUDFHost','TiWorker','TrustedInstaller','msiexec',
    'wermgr','WerFault','SpeechRuntime','PerfWatson2','SystemSettings',
    'GameBar','GameBarFTServer','NahimicSvc','NahimicSvc32','NahimicSvc64'
) | ForEach-Object { [void]$KnownProcesses.Add($_) }

# ── Whitelist de paths de apps legítimos ──────
# Apps que por design instalam em AppData ou são UWP
$LegitPathPatterns = @(
    'WindowsApps\\',
    'AppData\\Roaming\\Spotify\\',
    'AppData\\Roaming\\discord\\',
    'AppData\\Local\\Discord\\',
    'AppData\\Local\\slack\\',
    'AppData\\Roaming\\Zoom\\',
    'AppData\\Local\\Programs\\',
    'AppData\\Local\\Microsoft\\Teams\\',
    'AppData\\Roaming\\npm\\',
    'AppData\\Local\\GitHubDesktop\\',
    'AppData\\Local\\SquirrelTemp\\',
    'RivaTuner Statistics Server\\',
    'EVGA Precision',
    'ASUS\\',
    'ArmouryCrate',
    'AppData\\Local\\NVIDIA\\',
    'AppData\\Roaming\\Code\\',
    'AppData\\Local\\Programs\\Microsoft VS Code\\'
)

# ── Whitelist de temp files legítimos ─────────
# Libs Java, Node.js, build tools que ficam no Temp por design
$LegitTempPatterns = @(
    'lwjgl',           # Minecraft / LWJGL
    'jna-',            # Java Native Access
    'netty_',          # Netty networking (Java/Minecraft)
    'node-jiti',       # jiti TypeScript runner
    'node_modules',
    '\.tmp\.js$',      # build JS temp
    'electron-',
    'squirrel',
    'vscode-',
    'gradle-worker',
    'jetbrains',
    'idea_',
    'kotlin-',
    '\.tmp\.ps1$',
    'chocolatey',
    'scoop',
    'gradle-',
    'maven-',
    'nw-',
    'chromium-'
)

# ── Portas C2 clássicas ───────────────────────
$SuspectPorts = [System.Collections.Generic.HashSet[int]]::new()
@(1337,4444,4445,5554,5555,6666,6667,7777,8888,9999,31337,
  1080,4899,12345,54321,65535,2222,3333,6000,6001,6002,
  1234,11111,22222,33333,44444,55555) | ForEach-Object { [void]$SuspectPorts.Add($_) }

# ── IPs/ranges conhecidos legítimos (regex) ───
$LegitIPPatterns = @(
    '^127\.',                              # Loopback
    '^::1$',                               # Loopback IPv6
    '^0\.0\.0\.0$',                       # Wildcard
    '^::$',                                # IPv6 wildcard
    '^10\.',                               # RFC1918
    '^192\.168\.',                         # RFC1918
    '^172\.(1[6-9]|2\d|3[01])\.',        # RFC1918
    '^169\.254\.',                         # Link-local
    '^fe80:',                              # Link-local IPv6
    # Cloudflare
    '^162\.159\.', '^172\.64\.', '^172\.65\.', '^172\.66\.', '^172\.67\.',
    '^104\.(16|17|18|19|20|21)\.',
    '^2606:4700:', '^2803:f800:', '^2a06:98c0:', '^2a03:2880:',
    # Google / GCP
    '^142\.250\.', '^142\.251\.', '^172\.217\.', '^216\.58\.', '^209\.85\.',
    '^34\.', '^35\.', '^2607:f8b0:', '^2600:1901:',
    # Microsoft / Azure
    '^13\.107\.', '^20\.', '^40\.', '^52\.', '^13\.', '^2603:', '^2620:1ec:',
    # Facebook / Meta (WhatsApp)
    '^157\.240\.', '^179\.60\.', '^31\.13\.', '^2001:12e0:',
    # Akamai
    '^23\.', '^184\.', '^96\.', '^2600:1404:',
    # Fastly
    '^151\.101\.', '^199\.232\.',
    # Steam / Valve
    '^155\.133\.', '^185\.25\.18[0-3]\.', '^208\.64\.20[0-3]\.', '^2607:6bc0:',
    # Amazon / AWS
    '^54\.', '^18\.', '^3\.', '^2600:1f',
    # Discord
    '^66\.22\.',
    # Vercel / Netlify
    '^76\.76\.21\.', '^64\.190\.'
)

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
function Write-Section { param([string]$Title, [int]$Step, [int]$Total)
    Write-Host "`n[$Step/$Total] $Title" -ForegroundColor Cyan
    $Script:CurrentStep     = $Step
    $Script:CurrentStepName = $Title
    Invoke-WebServer
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Message,
        [ValidateSet('CRÍTICO','ALTO','MÉDIO','BAIXO')]
        [string]$Severity = 'MÉDIO',
        [int]$Score = 0
    )
    if ($Score -eq 0) {
        $Score = switch ($Severity) { 'CRÍTICO'{40} 'ALTO'{25} 'MÉDIO'{10} 'BAIXO'{5} }
    }
    $Script:Findings.Add(@{ Category=$Category; Message=$Message; Severity=$Severity; Score=$Score })
    $Script:RiskScore += $Score
    $color = switch ($Severity) { 'CRÍTICO'{'Red'} 'ALTO'{'Yellow'} 'MÉDIO'{'Magenta'} 'BAIXO'{'Gray'} }
    Write-Host "  [$Severity] $Message" -ForegroundColor $color
}

function Test-LegitIP { param([string]$IP)
    foreach ($p in $LegitIPPatterns) { if ($IP -match $p) { return $true } }
    return $false
}

function Test-LegitPath { param([string]$Path)
    # Os patterns já são regex com \\ representando \; não aplicar Escape (double-escape)
    foreach ($p in $LegitPathPatterns) { if ($Path -match $p) { return $true } }
    return $false
}

function Test-LegitTempFile { param([string]$Path)
    foreach ($p in $LegitTempPatterns) { if ($Path -match $p) { return $true } }
    return $false
}

function Get-ProcessRetry { param([int]$PID_)
    for ($i = 0; $i -lt 3; $i++) {
        $p = Get-Process -Id $PID_ -ErrorAction SilentlyContinue
        if ($p) { return $p }
        Start-Sleep -Milliseconds 120
    }
    return $null
}

function Get-RiskLevel {
    if ($Script:RiskScore -ge 80) { return 'CRÍTICO' }
    if ($Script:RiskScore -ge 40) { return 'ALTO'    }
    if ($Script:RiskScore -ge 15) { return 'MÉDIO'   }
    return 'BAIXO'
}

function Get-RiskColor {
    switch (Get-RiskLevel) {
        'CRÍTICO' { '#c0392b' } 'ALTO' { '#e67e22' } 'MÉDIO' { '#f39c12' } default { '#27ae60' }
    }
}

# ─────────────────────────────────────────────
#  COLETA
# ─────────────────────────────────────────────
Write-Host "`nSecurityAudit v3.0 — iniciando..." -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME  |  Usuário: $env:USERNAME  |  $($Script:StartTime.ToString('dd/MM/yyyy HH:mm:ss'))" -ForegroundColor Gray
Write-Host ("─" * 60) -ForegroundColor DarkGray

# ── 1. SISTEMA ────────────────────────────────
Write-Section "Sistema" 1 9
$OS   = Get-CimInstance Win32_OperatingSystem
$BIOS = Get-CimInstance Win32_BIOS
$CPU  = Get-CimInstance Win32_Processor | Select-Object -First 1
$NetAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
Add-Type -AssemblyName System.Web

$SysInfo = [PSCustomObject]@{
    Computador   = $env:COMPUTERNAME
    Dominio      = (Get-CimInstance Win32_ComputerSystem).Domain
    SO           = $OS.Caption
    Build        = $OS.BuildNumber
    UltimoReboot = $OS.LastBootUpTime
    UptimeHoras  = [math]::Round(($Script:StartTime - $OS.LastBootUpTime).TotalHours, 1)
    CPU          = $CPU.Name.Trim()
    RAM_GB       = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 1)
    BIOS         = $BIOS.SMBIOSBIOSVersion
    IPs          = ($NetAdapters | ForEach-Object { $_.IPAddress -join ',' }) -join ' | '
}
Write-Host "  $($SysInfo.SO) Build $($SysInfo.Build) — Uptime $($SysInfo.UptimeHoras)h" -ForegroundColor Gray

# ── 2. CONEXÕES ───────────────────────────────
Write-Section "Conexões de rede" 2 9

# Snapshot dos processos antes do netstat (reduz race condition)
$ProcessMap = @{}
Get-Process | ForEach-Object { $ProcessMap[$_.Id] = $_ }

$SystemPIDs = [System.Collections.Generic.HashSet[int]]::new()
@(0, 4) | ForEach-Object { [void]$SystemPIDs.Add($_) }  # Idle e System (kernel)

$Connections = Get-NetTCPConnection | Where-Object {
    $_.State -in 'Established','Listen' -and
    $_.RemoteAddress -notin '','0.0.0.0','::' -and
    -not (Test-LegitIP $_.RemoteAddress)          # descarta loopback e CDNs conhecidos
} | ForEach-Object {
    $pid_ = $_.OwningProcess
    $proc = if ($SystemPIDs.Contains($pid_)) {
        [PSCustomObject]@{ Name = 'System'; Path = '' }  # kernel — não flag como desconhecido
    } elseif ($ProcessMap.ContainsKey($pid_)) {
        $ProcessMap[$pid_]
    } else {
        Get-ProcessRetry $pid_
    }
    [PSCustomObject]@{
        Estado        = $_.State
        LocalAddress  = "$($_.LocalAddress):$($_.LocalPort)"
        RemoteAddress = "$($_.RemoteAddress):$($_.RemotePort)"
        PID           = $pid_
        Processo      = if ($proc) { $proc.Name }  else { '???' }
        Caminho       = if ($proc -and $proc.Path) { $proc.Path } else { '' }
        PortaRemota   = $_.RemotePort
        IP_Remoto     = $_.RemoteAddress
    }
}

# Segunda passagem: tenta resolver PIDs ainda desconhecidos (reduz race condition)
$unknownPIDs = $Connections | Where-Object { $_.Processo -eq '???' } |
    Select-Object -ExpandProperty PID -Unique
foreach ($upid in $unknownPIDs) {
    $p2 = Get-ProcessRetry $upid
    if ($p2) {
        foreach ($conn in ($Connections | Where-Object { $_.PID -eq $upid })) {
            $conn.Processo = $p2.Name
            $conn.Caminho  = if ($p2.Path) { $p2.Path } else { '' }
        }
    }
}

$SuspiciousConns = $Connections | Where-Object {
    $_.PortaRemota -in $SuspectPorts -and -not (Test-LegitIP $_.IP_Remoto)
}

# Deduplica processos desconhecidos por PID — um finding por processo, não por IP
$UnknownProcConns = $Connections | Where-Object {
    $_.Processo -eq '???' -and $_.Estado -eq 'Established'
} | Group-Object PID | ForEach-Object { $_.Group | Select-Object -First 1 }

$EstablishedConns = $Connections | Where-Object { $_.Estado -eq 'Established' }

foreach ($c in $SuspiciousConns) {
    Add-Finding 'Rede' "Porta C2 clássica $($c.PortaRemota) usada por '$($c.Processo)' → $($c.IP_Remoto)" 'CRÍTICO'
}
foreach ($c in $UnknownProcConns) {
    # Conta quantos IPs externos este PID tem
    $ipCount = ($Connections | Where-Object { $_.PID -eq $c.PID -and $_.Processo -eq '???' } | Select-Object -ExpandProperty IP_Remoto -Unique).Count
    $suffix  = if ($ipCount -gt 1) { " (+$($ipCount-1) outros IPs)" } else { '' }
    Add-Finding 'Rede' "Processo não identificado (PID $($c.PID)) → $($c.IP_Remoto)$suffix" 'ALTO'
}

Write-Host "  Externas: $(@($Connections).Count) | Suspeitas: $(@($SuspiciousConns).Count) | PID desconhecido: $(@($UnknownProcConns).Count)" -ForegroundColor Gray

# ── 3. PROCESSOS ──────────────────────────────
Write-Section "Processos" 3 9

# Cache de assinaturas por path — evita chamar Get-AuthenticodeSignature N vezes para o mesmo exe
$Script:SigCache = @{}
$_rawProcs = @(Get-Process -ErrorAction SilentlyContinue)
$_uniquePaths = $_rawProcs | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique
foreach ($_p in $_uniquePaths) {
    try {
        $r = Get-AuthenticodeSignature $_p -ErrorAction SilentlyContinue
        $Script:SigCache[$_p] = if ($r) { $r.Status.ToString() } else { 'Erro' }
    } catch { $Script:SigCache[$_p] = 'Erro' }
}
Write-Host "  Assinaturas verificadas: $($Script:SigCache.Count) paths únicos de $($_rawProcs.Count) processos" -ForegroundColor DarkGray

$AllProcesses = @($_rawProcs | Select-Object `
    @{N='Nome';      E={ $_.Name }},
    @{N='PID';       E={ $_.Id }},
    @{N='CPU_s';     E={ try { [math]::Round($_.CPU, 1) } catch { 0 } }},
    @{N='RAM_MB';    E={ try { [math]::Round($_.WorkingSet64 / 1MB, 1) } catch { 0 } }},
    @{N='Caminho';   E={ if ($_.Path) { $_.Path } else { '(sistema)' } }},
    @{N='Assinatura';E={ if ($_.Path) { $Script:SigCache[$_.Path] } else { 'N/A' } }},
    @{N='Empresa';   E={ try { if ($_.Company) { $_.Company } else { '' } } catch { '' } }},
    @{N='Inicio';    E={ try { if ($_.StartTime) { $_.StartTime.ToString('dd/MM HH:mm') } else { '' } } catch { '' } }}
)
Write-Host "  Processos: $($AllProcesses.Count)" -ForegroundColor Gray

$UnsignedProcs = $AllProcesses | Where-Object {
    $_.Assinatura -notin 'Valid','N/A','Erro' -and
    $_.Caminho -ne '(sistema)' -and
    $_.Nome -notin $KnownProcesses -and
    -not (Test-LegitPath $_.Caminho)
}

# Deduplica por nome (mesmo exe, múltiplas instâncias)
$SuspectPathProcs = $AllProcesses | Where-Object {
    $_.Caminho -match '(\\Temp\\[^\\]+\.(exe|dll|ps1|bat|vbs|js)$|\\Downloads\\[^\\]+\.exe$|\\Recycle|\\ProgramData\\[^\\]+\\[^\\]+\\[^\\]+\.exe)' -and
    $_.Caminho -ne '(sistema)' -and
    -not (Test-LegitPath $_.Caminho) -and
    $_.Nome -notin $KnownProcesses
} | Group-Object Nome | ForEach-Object { $_.Group | Select-Object -First 1 }

foreach ($p in $UnsignedProcs) {
    Add-Finding 'Processo' "Sem assinatura válida: '$($p.Nome)' — $($p.Caminho)" 'MÉDIO'
}
foreach ($p in $SuspectPathProcs) {
    Add-Finding 'Processo' "Path suspeito: '$($p.Nome)' — $($p.Caminho)" 'ALTO'
}

Write-Host "  Total: $(@($AllProcesses).Count) | Sem assinatura: $(@($UnsignedProcs).Count) | Path suspeito: $(@($SuspectPathProcs).Count)" -ForegroundColor Gray

# ── 4. PERSISTÊNCIA ───────────────────────────
Write-Section "Persistência" 4 9

$RunKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$SuspectRunPattern = '(\\Temp\\|AppData\\Roaming\\(?!Spotify|discord|Zoom|Microsoft|Code|Slack)[^\\]+\\[^\\]+\.exe|\.vbs\b|\.js\b|mshta|wscript|cscript|powershell.*-enc|-w.{0,5}hidden|bypass)'

$AutorunEntries = foreach ($key in $RunKeys) {
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $suspect = $_.Value -match $SuspectRunPattern
            if ($suspect) {
                Add-Finding 'Persistência' "Run key suspeita: '$($_.Name)' = '$($_.Value)'" 'ALTO'
            }
            [PSCustomObject]@{
                Chave    = ($key -replace '^HK[LC][MU]:\\','')
                Nome     = $_.Name
                Valor    = $_.Value
                Suspeito = if ($suspect) { '⚠ SIM' } else { 'não' }
            }
        }
    }
}

# Padrões de tasks legítimas conhecidas (ferramentas de tweak/debloat)
$LegitTaskWhitelist = @(
    'RemoveAI',          # RemoveWindowsAI / debloat Copilot
    'ChrisTitus',        # WinUtil
    'Sophia',            # Sophia Script
    'WinUtil',
    'BloatyNosy'
)

$SuspectTaskPattern = '(powershell.*-enc|mshta|wscript.*\.vbs|cscript|Temp\\|AppData\\Roaming\\(?!Spotify|discord|Zoom)[^\\]+\\|-w.{0,5}hidden|bypass|invoke-exp|downloadstring)'

$ScheduledTasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled'
} | ForEach-Object {
    $action   = $_.Actions | Where-Object { $_.Execute } | Select-Object -First 1
    $exe      = if ($action) { $action.Execute }   else { '' }
    $taskArgs = if ($action) { $action.Arguments } else { '' }
    $full     = "$exe $taskArgs".Trim()

    # Trigger summary
    $triggerDesc = ($_.Triggers | ForEach-Object {
        if ($_ -is [CimInstance]) {
            $t = $_.CimClass.CimClassName
            switch -Wildcard ($t) {
                '*Boot*'   { 'No boot'   }
                '*Logon*'  { 'No logon'  }
                '*Daily*'  { 'Diariamente' }
                '*Weekly*' { 'Semanal'   }
                '*Time*'   { 'Agendado'  }
                default    { $t -replace 'MSFT_Task','' }
            }
        }
    }) -join ', '
    if (-not $triggerDesc) { $triggerDesc = 'Manual' }

    $suspect = $full -match $SuspectTaskPattern
    # Descarta tasks de ferramentas legítimas conhecidas
    $isWhitelisted = $LegitTaskWhitelist | Where-Object { $_.TaskName -match $_ }
    if (-not $isWhitelisted) {
        $isWhitelisted = $LegitTaskWhitelist | Where-Object { $full -match $_ }
    }

    if ($suspect -and -not $isWhitelisted) {
        # Lê as primeiras 3 linhas do script referenciado para contexto
        $scriptRef = if ($taskArgs -match '([A-Z]:\\[^"\s]+\.(vbs|ps1|bat|js|cmd))') { $Matches[1] } else { '' }
        $scriptPreview = ''
        if ($scriptRef -and (Test-Path $scriptRef)) {
            $lines = Get-Content $scriptRef -TotalCount 3 -ErrorAction SilentlyContinue
            if ($lines) { $scriptPreview = " | Preview: $(($lines -join ' ').Substring(0, [Math]::Min(120, ($lines -join ' ').Length)))" }
        }
        $sev = if ($full -match '(invoke-exp|downloadstring|-enc|mshta|RunAsTI|TrustedInstaller)') { 'CRÍTICO' } else { 'ALTO' }
        Add-Finding 'Persistência' "Task '$($_.TaskName)' [$triggerDesc] → $full$scriptPreview" $sev
    }
    [PSCustomObject]@{
        Nome     = $_.TaskName
        Path     = $_.TaskPath
        Trigger  = $triggerDesc
        Estado   = $_.State
        Acao     = if ($full.Length -gt 120) { $full.Substring(0,120)+'...' } else { $full }
        Suspeito = if ($suspect -and -not $isWhitelisted) { '⚠ SIM' } else { 'não' }
    }
}

$SuspectServices = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '(System32|SysWOW64|Program Files|Windows|MsMpEng|RivaTuner|ASUS|Nahimic|nVidia|Intel|AMD|Realtek|Qualcomm|Logitech)' -and
    $_.State -eq 'Running'
} | ForEach-Object {
    Add-Finding 'Persistência' "Serviço em path incomum: '$($_.Name)' — $($_.PathName)" 'MÉDIO'
    [PSCustomObject]@{
        Nome    = $_.Name
        Display = $_.DisplayName
        Caminho = $_.PathName
        Inicio  = $_.StartMode
        Estado  = $_.State
    }
}

Write-Host "  Run keys: $(@($AutorunEntries).Count) | Tarefas: $(@($ScheduledTasks).Count) | Serviços incomuns: $(@($SuspectServices).Count)" -ForegroundColor Gray

# Scan direto em ProgramData por scripts não-assinados de vendors desconhecidos
$ProgramDataScripts = Get-ChildItem 'C:\ProgramData' -Recurse -Include *.ps1,*.vbs,*.js,*.bat,*.cmd -Depth 3 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '(Microsoft|Windows|ESET|Kaspersky|Symantec|Norton|Avast|Malware|Defender|Adobe|Intel|NVIDIA|AMD|Realtek|RemoveAI|RemoveWindows|SophiaScript|WinUtil)' -and
        $_.LastWriteTime -gt (Get-Date).AddDays(-30)
    } | ForEach-Object {
        $sig = (Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue).Status
        if ($sig -ne 'Valid') {
            $preview = (Get-Content $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue) -replace '\s+',' '
            $sev = if ($_.Name -match '(loader|inject|payload|bypass|dropper|rat|shell|miner)') { 'CRÍTICO' } else { 'ALTO' }
            Add-Finding 'Arquivo' "Script não assinado em ProgramData: $($_.FullName)$(if ($preview) { " | $($preview.Substring(0,[Math]::Min(80,$preview.Length)))" })" $sev
        }
        [PSCustomObject]@{
            Arquivo    = $_.FullName
            Modificado = $_.LastWriteTime.ToString('dd/MM HH:mm')
            KB         = [math]::Round($_.Length / 1KB, 1)
            Assinatura = if ($sig) { $sig } else { 'N/A' }
        }
    }

# ── 5. USUÁRIOS ───────────────────────────────
Write-Section "Usuários" 5 9

$LocalUsers = Get-LocalUser | ForEach-Object {
    [PSCustomObject]@{
        Nome             = $_.Name
        Habilitado       = $_.Enabled
        UltimoLogin      = if ($_.LastLogon) { $_.LastLogon.ToString('dd/MM/yyyy HH:mm') } else { 'Nunca' }
        SenhaNuncaExpira = $_.PasswordNeverExpires
        SenhaEm          = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('dd/MM/yyyy') } else { '' }
        Descricao        = $_.Description
    }
}

# Get-LocalGroupMember falha com contas Microsoft Account — usar net localgroup como fallback
$Admins = try {
    $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
    if ($members.Count -eq 0) { throw }
    $members
} catch {
    try {
        $members = @(Get-LocalGroupMember -Group 'Administradores' -ErrorAction Stop)
        if ($members.Count -eq 0) { throw }
        $members
    } catch {
        # Fallback: net localgroup (funciona com contas Microsoft)
        $grpOut = (net localgroup Administradores 2>$null) + (net localgroup Administrators 2>$null)
        @($grpOut | Where-Object {
            $_ -match '\S' -and
            $_ -notmatch '^-{3}' -and
            $_ -notmatch 'Alias|Comment|Comentário|Members|Membros|command completed|executado com êxito'
        } | Select-Object -Skip 1 | ForEach-Object {
            [PSCustomObject]@{ Name = $_.Trim(); ObjectClass = 'User'; PrincipalSource = 'Local' }
        } | Where-Object { $_.Name -ne '' })
    }
}
$SystemAccounts = @('Administrator','Administrador','DefaultAccount','WDAGUtilityAccount','Guest','Convidado')
foreach ($u in ($LocalUsers | Where-Object { $_.Habilitado -and $_.SenhaNuncaExpira -and $_.Nome -notin $SystemAccounts })) {
    Add-Finding 'Usuário' "Conta ativa '$($u.Nome)' com senha que nunca expira" 'BAIXO'
}
Write-Host "  Locais: $(@($LocalUsers).Count) | Admins: $(@($Admins).Count)" -ForegroundColor Gray

# ── 6. CREDENCIAIS ────────────────────────────
Write-Section "Credenciais e senhas" 6 9

$SavedCreds = [System.Collections.Generic.List[PSCustomObject]]::new()

# Helper: extrai URL/nome legível do recurso
function Format-CredUrl ([string]$raw) {
    if ($raw -match 'https?://([^/?#:]+)')  { return $Matches[1] }
    if ($raw -match 'ftp://([^/?#:]+)')     { return $Matches[1] }
    if ($raw -match '^(?:LegacyGeneric:target=|TERMSRV/|WindowsLive:name=|Domain:target=)(.+)') { return $Matches[1] }
    if ($raw -match '^MicrosoftOffice')     { return 'Microsoft Office' }
    if ($raw -match '^Adobe')               { return 'Adobe' }
    if ($raw.Length -gt 60)                { return ($raw -split '[/\\]' | Where-Object { $_ } | Select-Object -Last 1) }
    return $raw
}

# 1. Windows Credential Manager (cmdkey /list)
try {
    $cmdout = cmdkey /list 2>&1
    $target = ''; $user = ''; $type = ''
    foreach ($line in $cmdout) {
        $ln = $line.ToString().Trim()
        if ($ln -match 'Destino:|Target:') {
            $target = ($ln -split ':\s*', 2)[-1].Trim(); $user = ''; $type = ''
        } elseif ($ln -match 'Tipo:|Type:') {
            $type = ($ln -split ':\s*', 2)[-1].Trim()
        } elseif ($ln -match 'Usuário:|User:') {
            $user = ($ln -split ':\s*', 2)[-1].Trim()
            if ($target -and $user -and $target -notmatch '^\*') {
                $SavedCreds.Add([PSCustomObject]@{
                    Fonte     = 'Windows'
                    UrlClean  = Format-CredUrl $target
                    Login     = $user
                    Senha     = '●●●●●●●●'
                    Indicador = '💾 Armazenada pelo Windows'
                })
            }
        }
    }
} catch {}

# 2. Windows Vault (PasswordVault — retorna a senha real para mostrar parcialmente)
try {
    [Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime] | Out-Null
    $vault = [Windows.Security.Credentials.PasswordVault]::new()
    foreach ($c in @($vault.RetrieveAll())) {
        try { $c.RetrievePassword() } catch {}
        $pwd = $c.Password
        # Mostrar primeiras 3 letras + *** (ex: "fer***")
        $masked = if ($pwd -and $pwd.Length -gt 3) {
            $pwd.Substring(0, [Math]::Min(3, $pwd.Length - 1)) + '***'
        } elseif ($pwd -and $pwd.Length -gt 0) { '***' } else { '[vazia]' }
        $isWeak  = $pwd -and $pwd.Length -lt 8
        $isDigit = $pwd -and ($pwd -match '^[0-9]+$')
        $ind = if ($isWeak -and $isDigit) { "⚠ FRACA — somente números ($($pwd.Length) dígitos)" }
               elseif ($isWeak)           { "⚠ FRACA — senha com $($pwd.Length) caractere(s)" }
               else                       { '💾 Salva no Windows Vault' }
        $SavedCreds.Add([PSCustomObject]@{
            Fonte     = 'Windows Vault'
            UrlClean  = Format-CredUrl $c.Resource
            Login     = $c.UserName
            Senha     = $masked
            Indicador = $ind
        })
        if ($isWeak) { Add-Finding 'Credencial' "Senha fraca no Vault: '$($c.Resource)' ($($pwd.Length) chars)" 'MÉDIO' }
    }
} catch {}

# 3. Detecção de bancos de senhas de browsers
foreach ($b in @(
    @{ Nome = 'Chrome'; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" },
    @{ Nome = 'Edge';   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" },
    @{ Nome = 'Brave';  Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data" },
    @{ Nome = 'Opera';  Path = "$env:APPDATA\Opera Software\Opera Stable\Login Data" })) {
    if (Test-Path $b.Path) {
        $sz = [math]::Round((Get-Item $b.Path).Length / 1KB, 1)
        $SavedCreds.Add([PSCustomObject]@{
            Fonte     = $b.Nome
            UrlClean  = "$($b.Nome) (browser)"
            Login     = "Senhas salvas no $($b.Nome) detectadas em disco"
            Senha     = '[criptografado]'
            Indicador = "🌐 Banco de senhas do $($b.Nome) — ${sz} KB no disco"
        })
        Add-Finding 'Credencial' "Banco de senhas do $($b.Nome) detectado em disco (${sz} KB)" 'BAIXO'
    }
}

Write-Host "  Credenciais: $(@($SavedCreds).Count)" -ForegroundColor Gray

# ── 7. EVENTOS ────────────────────────────────
Write-Section "Eventos de segurança" 7 9

function Get-SecEvent { param([int]$Id, [int]$Max = 500)
    try { Get-WinEvent -LogName Security -MaxEvents $Max -FilterXPath "*[System[EventID=$Id]]" -EA Stop }
    catch { @() }
}

$FailedLogons = Get-SecEvent 4625 2000

# Mapeamento de tipos de logon
$LogonTypeMap = @{
    2  = 'Interativo (teclado)'
    3  = 'Rede'
    4  = 'Lote (Batch)'
    5  = 'Serviço'
    7  = 'Desbloqueio de tela'
    8  = 'Rede (texto claro)'
    10 = 'RDP/RemoteInteractive'
    11 = 'Cached Interactive'
}

# Tabela detalhada por evento (IP, tipo de logon, estação, hora)
$FailedDetails = @($FailedLogons | ForEach-Object {
    $user    = try { $_.Properties[5].Value  } catch { '-' }
    $domain  = try { $_.Properties[6].Value  } catch { '-' }
    $logonT  = try { [int]$_.Properties[10].Value } catch { 0 }
    $ip      = try { $_.Properties[19].Value } catch { '-' }
    $ws      = try { $_.Properties[13].Value } catch { '-' }
    $hora    = $_.TimeCreated.ToString('dd/MM HH:mm')
    $tipotxt = if ($LogonTypeMap[$logonT]) { $LogonTypeMap[$logonT] } else { "Tipo $logonT" }

    # Flag logons REMOTOS (rede/RDP) mesmo que seja apenas 1
    $isRemote = $logonT -in @(3, 10) -or (
        $ip -and $ip -notin @('-', '', '127.0.0.1', '::1', '-')
    )
    if ($isRemote) {
        $userStr = if ($user -and $user -ne '-') { $user } else { '(desconhecido)' }
        Add-Finding 'Evento' "Falha de logon REMOTA: '$userStr' de $ip ($tipotxt) em $hora" 'ALTO'
    }

    [PSCustomObject]@{
        Hora      = $hora
        Usuario   = if ($user -and $user -ne '-') { $user } else { '(desconhecido)' }
        Dominio   = if ($domain -and $domain -ne '-') { $domain } else { '-' }
        TipoLogon = $tipotxt
        IP        = if ($ip -and $ip -ne '-') { $ip } else { '-' }
        Estacao   = if ($ws -and $ws -ne '-') { $ws } else { '-' }
    }
})

# Agrupado por usuário para detectar brute-force (≥20 falhas)
$FailedByUser = @($FailedLogons | Group-Object { $_.Properties[5].Value } |
    Sort-Object Count -Descending | Select-Object -First 10 |
    ForEach-Object {
        $user = $_.Name
        if ($_.Count -ge 20 -and $user -ne '-' -and $user -ne '') {
            Add-Finding 'Evento' "Possível brute-force: $($_.Count) falhas para '$user'" 'ALTO'
        }
        [PSCustomObject]@{ Usuario = $user; Tentativas = $_.Count }
    })

$AccountsCreated = Get-SecEvent 4720 200 | ForEach-Object {
    $newUser = $_.Properties[0].Value
    $by      = $_.Properties[4].Value
    Add-Finding 'Evento' "Conta criada: '$newUser' por '$by' em $($_.TimeCreated.ToString('dd/MM HH:mm'))" 'ALTO'
    [PSCustomObject]@{ Hora=$_.TimeCreated.ToString('dd/MM HH:mm'); NovaConta=$newUser; CriadaPor=$by }
}

$AdminAdded = Get-SecEvent 4732 200 | Where-Object { $_.Properties[2].Value -match 'Admin' } | ForEach-Object {
    Add-Finding 'Evento' "Adicionado ao grupo Admin: '$($_.Properties[0].Value)'" 'CRÍTICO'
    [PSCustomObject]@{ Hora=$_.TimeCreated.ToString('dd/MM HH:mm'); Usuario=$_.Properties[0].Value; Grupo=$_.Properties[2].Value }
}

$LogCleared = Get-SecEvent 1102 50 | ForEach-Object {
    Add-Finding 'Evento' "Log de segurança LIMPO em $($_.TimeCreated.ToString('dd/MM/yyyy HH:mm'))" 'CRÍTICO'
    [PSCustomObject]@{ Hora=$_.TimeCreated.ToString('dd/MM/yyyy HH:mm'); Evento='Log de segurança limpo' }
}

$SuspectCmdPattern = '(-enc[^o]|invoke-expression|iex\s|downloadstring|webclient\.download|net\s+user.*/add|mimikatz|procdump|fgdump|gsecdump|wce\.exe|-w\s+hidden|bypass.*execution|regsvr32.*/s.*/u)'
$SuspectCmdLines = Get-SecEvent 4688 2000 | ForEach-Object {
    $cmd = try { $_.Properties[8].Value } catch { '' }
    if ($cmd -match $SuspectCmdPattern) {
        $short = if ($cmd.Length -gt 150) { $cmd.Substring(0,150)+'...' } else { $cmd }
        Add-Finding 'Evento' "Cmdline suspeita: $short" 'CRÍTICO'
        [PSCustomObject]@{ Hora=$_.TimeCreated.ToString('dd/MM HH:mm'); Processo=$_.Properties[5].Value; CmdLine=$short }
    }
} | Where-Object { $_ }

$RemoteFailCount = @($FailedDetails | Where-Object { $_.IP -notin @('-','127.0.0.1','::1') }).Count
Write-Host "  Falhas logon: $(@($FailedLogons).Count) ($RemoteFailCount remotas) | Contas criadas: $(@($AccountsCreated).Count) | Log limpo: $(@($LogCleared).Count)" -ForegroundColor Gray

# ── 7. ARQUIVOS SUSPEITOS ─────────────────────
Write-Section "Arquivos suspeitos" 8 9

# Normaliza e deduplica dirs (TEMP e LOCALAPPDATA\Temp apontam para o mesmo dir no Windows)
$SuspectDirs = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads") |
    ForEach-Object { $_.TrimEnd('\') } | Sort-Object -Unique
$SeenFiles   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

$RecentFiles = foreach ($dir in $SuspectDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem $dir -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.js,*.hta,*.scr,*.cmd -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and
        -not (Test-LegitTempFile $_.FullName) -and
        $_.Name -notmatch 'SecurityAudit'
    } | ForEach-Object {
        if ($SeenFiles.Add($_.FullName)) {
            $sig = (Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue).Status
            if ($sig -ne 'Valid') {
                Add-Finding 'Arquivo' "Executável sem assinatura em path suspeito: $($_.FullName)" 'MÉDIO'
            }
            [PSCustomObject]@{
                Arquivo    = $_.FullName
                Modificado = $_.LastWriteTime.ToString('dd/MM HH:mm')
                KB         = [math]::Round($_.Length / 1KB, 1)
                Assinatura = if ($sig) { $sig } else { 'N/A' }
            }
        }
    }
}

$HostsPath    = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsEntries = Get-Content $HostsPath -ErrorAction SilentlyContinue |
    Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
$SuspectHosts = $HostsEntries | Where-Object {
    $_ -match '(google|microsoft|windows\.com|windowsupdate|antivirus|kaspersky|avast|norton|bitdefender|eset|malware|virustotal)'
}
foreach ($h in $SuspectHosts) {
    Add-Finding 'Arquivo' "Entrada suspeita no HOSTS: '$h'" 'CRÍTICO'
}

Write-Host "  Arquivos suspeitos: $(@($RecentFiles).Count) | Hosts entries: $(@($HostsEntries).Count)" -ForegroundColor Gray

# ── 8. REDE ADICIONAL ─────────────────────────
Write-Section "Portas e DNS" 9 9

$OpenPorts = Get-NetTCPConnection -State Listen | ForEach-Object {
    $proc = if ($ProcessMap.ContainsKey($_.OwningProcess)) { $ProcessMap[$_.OwningProcess] } else { Get-ProcessRetry $_.OwningProcess }
    [PSCustomObject]@{
        Porta    = $_.LocalPort
        Endereco = $_.LocalAddress
        PID      = $_.OwningProcess
        Processo = if ($proc) { $proc.Name } else { '???' }
        Caminho  = if ($proc -and $proc.Path) { $proc.Path } else { '' }
    }
} | Sort-Object Porta

$DNSCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object { $_.Type -eq 1 } |
    Select-Object -First 60 Entry, Data, TimeToLive |
    Sort-Object Entry

Write-Host "  Portas listen: $(@($OpenPorts).Count) | DNS cache: $(@($DNSCache).Count)" -ForegroundColor Gray

# ─────────────────────────────────────────────
#  HTML
# ─────────────────────────────────────────────
Write-Host "`nGerando relatório HTML..." -ForegroundColor Cyan

function ConvertTo-HtmlTable {
    param([object[]]$Data, [string]$EmptyMsg = 'Nenhum item encontrado.')
    if (-not $Data -or $Data.Count -eq 0) { return "<p class='empty'>✓ $EmptyMsg</p>" }
    $headers = $Data[0].PSObject.Properties.Name
    $html = "<div class='tw'><table><thead><tr>"
    foreach ($h in $headers) { $html += "<th>$h</th>" }
    $html += "</tr></thead><tbody>"
    foreach ($row in $Data) {
        $cls = if ($row.PSObject.Properties['Suspeito'] -and $row.Suspeito -match 'SIM') { ' class="suspect"' } else { '' }
        $html += "<tr$cls>"
        foreach ($h in $headers) {
            $val = if ($null -eq $row.$h) { '' } else { $row.$h.ToString() }
            $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($val))</td>"
        }
        $html += "</tr>"
    }
    $html += "</tbody></table></div>"
    return $html
}

$RiskLevel = Get-RiskLevel
$RiskColor = Get-RiskColor
$EndTime   = Get-Date
$Duration  = [math]::Round(($EndTime - $Script:StartTime).TotalSeconds, 1)

$FindingsHTML = if ($Script:Findings.Count -eq 0) {
    "<p class='clean'>✓ Nenhum indicador de comprometimento detectado.</p>"
} else {
    $bySev = $Script:Findings | Group-Object { $_['Severity'] }
    $order = @('CRÍTICO','ALTO','MÉDIO','BAIXO')
    ($order | ForEach-Object {
        $sev   = $_
        $group = $bySev | Where-Object Name -eq $sev
        if (-not $group) { return }
        $cls = switch ($sev) { 'CRÍTICO'{'sc'} 'ALTO'{'sh2'} 'MÉDIO'{'sm'} 'BAIXO'{'sl2'} }
        "<div class='fg'><span class='sl $cls'>$sev ($($group.Group.Count))</span><ul>" +
        ($group.Group | ForEach-Object { "<li><b>[$($_['Category'])]</b> $($_['Message'])</li>" } | Out-String) +
        "</ul></div>"
    }) -join ''
}

# Gera HTML estilo Apple Passwords — URL, Login, Senha parcial, Indicador
$CredentialsHTML = if (@($SavedCreds).Count -eq 0) {
    "<div class='empty'>&#10003; Nenhuma credencial ou banco de senhas detectado</div>"
} else {
    "<div class='cred-grid'>" + ($SavedCreds | ForEach-Object {
        $indCls = if ($_.Indicador -match '⚠')  { 'cr-ind-warn' }
                  elseif ($_.Indicador -match '🌐') { 'cr-ind-info' }
                  else { '' }
        "<div class='cred-row'>" +
        "<div class='cr-f'><span class='cr-l'>&#127760; URL / Servi&ccedil;o</span><span class='cr-v cr-url'>$([System.Web.HttpUtility]::HtmlEncode($_.UrlClean))</span></div>" +
        "<div class='cr-f'><span class='cr-l'>&#128100; Login</span><span class='cr-v'>$([System.Web.HttpUtility]::HtmlEncode($_.Login))</span></div>" +
        "<div class='cr-f'><span class='cr-l'>&#128273; Senha</span><span class='cr-v cr-pw'>$($_.Senha)</span></div>" +
        "<div class='cr-f'><span class='cr-l'>&#8505; Indicador</span><span class='cr-v $indCls'>$($_.Indicador)</span></div>" +
        "</div>"
    }) -join '' + "</div>"
}

# Seções do relatório
$Sections = @(
    @{ Title="🔐 Credenciais salvas — Credential Manager, Vault e Browsers"; Html=$CredentialsHTML;                                                           Cnt=@($SavedCreds).Count     },
    @{ Title="Conexões externas estabelecidas";             Data=$EstablishedConns;                                              Cnt=$EstablishedConns.Count  },
    @{ Title="Portas abertas (LISTEN)";                     Data=$OpenPorts;                                                     Cnt=$OpenPorts.Count         },
    @{ Title="Processos (top 80 por RAM)";                  Data=($AllProcesses | Sort-Object RAM_MB -Descending | Select-Object -First 80); Cnt=@($AllProcesses).Count },
    @{ Title="Run keys — autorun de registro";              Data=$AutorunEntries;                                                Cnt=$AutorunEntries.Count    },
    @{ Title="Tarefas agendadas (não-Microsoft)";           Data=$ScheduledTasks;                                                Cnt=$ScheduledTasks.Count    },
    @{ Title="Serviços em path incomum";                    Data=$SuspectServices;                                               Cnt=$SuspectServices.Count   },
    @{ Title="Usuários locais";                             Data=$LocalUsers;                                                    Cnt=$LocalUsers.Count        },
    @{ Title="Grupo Administradores";                       Data=($Admins | Select-Object Name,ObjectClass,PrincipalSource);    Cnt=$Admins.Count            },
    @{ Title="Falhas de logon — detalhes por evento (ID 4625)"; Data=$FailedDetails;                                         Cnt=@($FailedDetails).Count  },
    @{ Title="Falhas de logon — agrupado por usuário";    Data=$FailedByUser;                                                  Cnt=$FailedLogons.Count      },
    @{ Title="Contas criadas recentemente (ID 4720)";       Data=$AccountsCreated;                                               Cnt=$AccountsCreated.Count   },
    @{ Title="Adicionados ao grupo Admin (ID 4732)";        Data=$AdminAdded;                                                    Cnt=$AdminAdded.Count        },
    @{ Title="Log de segurança limpo (ID 1102)";            Data=$LogCleared;                                                    Cnt=$LogCleared.Count        },
    @{ Title="Cmdlines suspeitas (ID 4688)";                Data=$SuspectCmdLines;                                               Cnt=$SuspectCmdLines.Count   },
    @{ Title="Arquivos sem assinatura em paths suspeitos";  Data=$RecentFiles;                                                   Cnt=@($RecentFiles).Count        },
    @{ Title="Scripts não assinados em ProgramData";        Data=$ProgramDataScripts;                                            Cnt=@($ProgramDataScripts).Count },
    @{ Title="Cache DNS";                                   Data=$DNSCache;                                                      Cnt=$DNSCache.Count          }
)

$SectionsHTML = ($Sections | ForEach-Object {
    $i    = [array]::IndexOf($Sections, $_)
    $body = if ($_.Html) { $_.Html } else { ConvertTo-HtmlTable $_.Data }
    "<div class='sec'><div class='sh' onclick=""t($i)""><h2>$($_.Title)</h2><span class='cnt'>$($_.Cnt)</span><span class='chv' id='c$i'>▶</span></div><div class='sb' id='b$i'>$body</div></div>"
}) -join ''

# Pré-computar contadores (expressões complexas dentro de here-string podem falhar em algumas versões do PS)
$cConns      = @($EstablishedConns).Count
$cSuspConns  = @($SuspiciousConns).Count
$cProcs      = @($AllProcesses).Count
$cUnsigned   = @($UnsignedProcs).Count
$cUsers      = @($LocalUsers).Count
$cAdmins     = @($Admins).Count
$cCreds      = @($SavedCreds).Count
$cFailedLog  = @($FailedLogons).Count
$cRemoteFail = @($FailedDetails | Where-Object { $_.IP -notin @('-','127.0.0.1','::1') }).Count
$cLogCleared = @($LogCleared).Count
$cFiles      = @($RecentFiles).Count

$HTML = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecurityAudit — $env:COMPUTERNAME</title>
<style>
:root{--bg:#050b14;--sf:#0a1628;--sf2:#0f2040;--bd:#1a3a5c;--p:#00d4ff;--g:#00ff88;--r:#ff4444;--a:#ffaa00;--pu:#a855f7;--bl:#3b82f6;--tx:#cde0f0;--tx2:#6b9cc4;--mut:#4a7aa0}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);font-size:13px;line-height:1.6;padding-bottom:60px}
.hdr{background:linear-gradient(135deg,var(--sf2) 0%,var(--sf) 100%);border-bottom:1px solid var(--bd);padding:16px 28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}
.hdr h1{font-size:13px;font-weight:700;color:var(--p);letter-spacing:1.5px;text-transform:uppercase}
.meta{font-size:11px;color:var(--mut);margin-top:3px}
.pill{padding:5px 16px;border-radius:4px;font-weight:700;font-size:12px;letter-spacing:.5px;border:1px solid}
.wrap{max-width:1300px;margin:0 auto;padding:18px 16px}
.sr{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:18px 24px;margin-bottom:14px;display:flex;align-items:center;gap:20px}
.sn{font-size:44px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.ss{font-size:11px;color:var(--tx2);margin-top:4px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.kpi{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:13px 16px;transition:border-color .2s}
.kpi:hover{border-color:rgba(0,212,255,.25)}
.kpi .l{font-size:9px;color:var(--mut);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.kpi .v{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}
.kpi .s{font-size:11px;color:var(--tx2);margin-top:3px}
.fb{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:16px 22px;margin-bottom:14px}
.fb h2{font-size:12px;font-weight:700;margin-bottom:12px;color:var(--tx2);text-transform:uppercase;letter-spacing:.5px}
.fg{margin-bottom:12px}
.sl{display:inline-flex;align-items:center;font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;margin-bottom:6px;letter-spacing:.5px;text-transform:uppercase}
.sc{background:rgba(255,68,68,.15);border:1px solid rgba(255,68,68,.3);color:#ff7a7a}
.sh2{background:rgba(255,170,0,.1);border:1px solid rgba(255,170,0,.3);color:#ffcc44}
.sm{background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.3);color:#c084fc}
.sl2{background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);color:#60a5fa}
.fg ul{padding-left:0;list-style:none}
.fg li{padding:5px 10px;margin-bottom:3px;font-size:12px;background:rgba(255,255,255,.02);border-left:2px solid var(--bd);border-radius:0 4px 4px 0;color:var(--tx2)}
.clean{color:var(--g);font-weight:500;font-size:12px;padding:6px 0}
.sec{background:var(--sf);border:1px solid var(--bd);border-radius:10px;margin-bottom:8px;overflow:hidden;transition:border-color .2s}
.sec:hover{border-color:rgba(0,212,255,.2)}
.sh{padding:11px 18px;background:var(--sf2);border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none;transition:background .2s}
.sh:hover{background:rgba(0,212,255,.05)}
.sh h2{font-size:12px;font-weight:600;flex:1;color:var(--tx);letter-spacing:.2px}
.cnt{font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(0,212,255,.08);color:var(--p);border:1px solid rgba(0,212,255,.18);font-weight:700}
.chv{font-size:10px;color:var(--mut);transition:transform .25s}
.sb{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .35s ease,padding .35s}
.sb.open{max-height:6000px;padding:12px 18px}
.tw{overflow-x:auto;border-radius:6px}
table{width:100%;border-collapse:collapse;font-size:11.5px}
th{background:rgba(0,0,0,.35);color:var(--mut);font-weight:600;text-align:left;padding:7px 10px;border-bottom:1px solid var(--bd);white-space:nowrap;font-size:10px;text-transform:uppercase;letter-spacing:.5px}
td{padding:6px 10px;border-bottom:1px solid rgba(26,58,92,.35);vertical-align:top;max-width:420px;word-break:break-all;color:var(--tx2)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(0,212,255,.03);color:var(--tx)}
tr.suspect td{background:rgba(255,68,68,.04)}
tr.suspect:hover td{background:rgba(255,68,68,.08);color:var(--tx)}
.empty{color:var(--g);font-size:12px;display:flex;align-items:center;gap:8px;padding:6px 0}
.cred-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:8px}
.cred-row{background:var(--sf2);border:1px solid var(--bd);border-radius:10px;padding:14px 18px;display:flex;flex-direction:column;transition:border-color .2s}
.cred-row:hover{border-color:rgba(0,212,255,.25)}
.cr-f{display:grid;grid-template-columns:130px 1fr;align-items:baseline;padding:6px 0;border-bottom:1px solid rgba(26,58,92,.3)}
.cr-f:last-child{border-bottom:none}
.cr-l{font-size:9px;font-weight:700;color:var(--mut);text-transform:uppercase;letter-spacing:.8px;white-space:nowrap}
.cr-v{font-size:12px;color:var(--tx2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.cr-url{color:var(--p);font-weight:600}
.cr-pw{font-family:'Cascadia Code',Consolas,monospace;color:var(--tx);font-size:13px;letter-spacing:1px}
.cr-ind-warn{color:var(--a);font-weight:600}
.cr-ind-info{color:#60a5fa}
.foot{text-align:center;color:var(--mut);font-size:11px;padding:22px;border-top:1px solid var(--bd);margin-top:8px;line-height:1.8}
.foot a{color:var(--p);text-decoration:none}
.foot a:hover{text-decoration:underline}
.back-top{position:fixed;bottom:22px;right:22px;width:38px;height:38px;background:var(--sf2);border:1px solid var(--bd);border-radius:8px;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:13px;color:var(--tx2);transition:all .2s;text-decoration:none;z-index:50}
.back-top:hover{background:rgba(0,212,255,.1);border-color:var(--p);color:var(--p)}
@media(max-width:900px){.g4{grid-template-columns:1fr 1fr}}
@media(max-width:540px){.g4{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <div class="hdr h1">&#128274; SecurityAudit v3.0 — $env:COMPUTERNAME</div>
    <div class="meta">$env:USERNAME &nbsp;·&nbsp; $($Script:StartTime.ToString('dd/MM/yyyy HH:mm:ss')) &nbsp;·&nbsp; ${Duration}s</div>
  </div>
  <span class="pill" style="color:$RiskColor;border-color:${RiskColor}88;background:${RiskColor}18">$RiskLevel</span>
</div>
<div class="wrap">
<div class="sr">
  <div class="sn" style="color:$RiskColor">$($Script:RiskScore)</div>
  <div>
    <div style="font-weight:700;color:$RiskColor;font-size:14px;letter-spacing:.5px">$RiskLevel</div>
    <div class="ss">$($Script:Findings.Count) indicador(es) de comprometimento detectados</div>
  </div>
</div>
<div class="g4">
  <div class="kpi"><div class="l">Sistema</div><div class="v" style="font-size:12px;font-weight:600;padding-top:4px">$($SysInfo.SO -replace 'Microsoft ','')</div><div class="s">Build $($SysInfo.Build)</div></div>
  <div class="kpi"><div class="l">Uptime</div><div class="v">$($SysInfo.UptimeHoras)h</div><div class="s">Reboot: $($OS.LastBootUpTime.ToString('dd/MM HH:mm'))</div></div>
  <div class="kpi"><div class="l">Conexões externas</div><div class="v">$cConns</div><div class="s">Suspeitas: $cSuspConns</div></div>
  <div class="kpi"><div class="l">Processos</div><div class="v">$cProcs</div><div class="s">Sem assinatura: $cUnsigned</div></div>
</div>
<div class="fb"><h2>&#9888; Indicadores de Comprometimento</h2>$FindingsHTML</div>
$SectionsHTML
</div>
<a href="#" class="back-top" title="Topo">&#9650;</a>
<div class="foot">
  SecurityAudit v3.0 &nbsp;·&nbsp; $env:COMPUTERNAME &nbsp;·&nbsp; $($EndTime.ToString('dd/MM/yyyy HH:mm:ss'))<br>
  by <a href="https://github.com/ferpgshy" target="_blank">Fernando Garcia</a> &nbsp;·&nbsp; github.com/ferpgshy
</div>
<script>
function t(i){var b=document.getElementById('b'+i);var c=document.getElementById('c'+i);var o=b.classList.toggle('open');if(c)c.style.transform=o?'rotate(90deg)':''}
</script>
</body></html>
"@

try {
    $HTML | Out-File -FilePath $Script:ReportHTML -Encoding UTF8 -Force -ErrorAction Stop
    Write-Host "  HTML salvo: $Script:ReportHTML" -ForegroundColor DarkGray
} catch {
    Write-Host "  [ERRO] Falha ao salvar HTML: $_" -ForegroundColor Red
}

# ─────────────────────────────────────────────
#  TXT
# ─────────────────────────────────────────────
$TXTFindings = if ($Script:Findings.Count -eq 0) {
    "  Nenhum IOC encontrado."
} else {
    ($Script:Findings | ForEach-Object { "  [$($_['Severity'])][$($_['Category'])] $($_['Message'])" }) -join "`n"
}

@"
════════════════════════════════════════════════════
  SECURITYAUDIT v3.0 — $env:COMPUTERNAME
  $($Script:StartTime.ToString('dd/MM/yyyy HH:mm:ss'))
════════════════════════════════════════════════════

RISCO  : $RiskLevel ($($Script:RiskScore) pts)
IOCs   : $($Script:Findings.Count)

$TXTFindings

RESUMO:
  SO             : $($SysInfo.SO) Build $($SysInfo.Build)
  Uptime         : $($SysInfo.UptimeHoras)h
  Conexões ext.  : $cConns ($cSuspConns suspeitas)
  Processos      : $cProcs ($cUnsigned sem assinatura)
  Usuários       : $cUsers ($cAdmins admins)
  Credenciais    : $cCreds detectadas
  Falhas logon   : $cFailedLog ($cRemoteFail remotas)
  Log limpo      : $cLogCleared vezes
  Arquivos susp. : $cFiles

HTML : $Script:ReportHTML
════════════════════════════════════════════════════
"@ | Out-File -FilePath $Script:ReportTXT -Encoding UTF8 -Force

# Sinaliza a interface web que a análise terminou
$Script:Duration_   = $Duration.ToString()
$Script:ReportReady = $true
Invoke-WebServer  # processa qualquer request pendente imediatamente

# ─────────────────────────────────────────────
#  FINAL
# ─────────────────────────────────────────────
Write-Host "`n$("═"*55)" -ForegroundColor DarkGray
Write-Host "  CONCLUÍDO em ${Duration}s" -ForegroundColor White
Write-Host "$("═"*55)" -ForegroundColor DarkGray
Write-Host "  Risco  : " -NoNewline
Write-Host $RiskLevel -ForegroundColor $(switch($RiskLevel){'CRÍTICO'{'Red'}'ALTO'{'Yellow'}'MÉDIO'{'Magenta'}default{'Green'}})
Write-Host "  Score  : $($Script:RiskScore) pts  |  IOCs: $($Script:Findings.Count)"
Write-Host ""
Write-Host "  HTML   : $Script:ReportHTML" -ForegroundColor Cyan
Write-Host "  TXT    : $Script:ReportTXT"  -ForegroundColor Cyan
Write-Host "$("═"*55)" -ForegroundColor DarkGray

if ($Script:Listener) {
    Write-Host "  Interface web: http://localhost:$Script:Port — aguardando browser..." -ForegroundColor Cyan
    # Fica servindo até o browser carregar /report, ou no máximo 30s
    # Sai 3s após servir o relatório (tempo do browser processar a página)
    $t_       = [System.Diagnostics.Stopwatch]::StartNew()
    $servedAt = $null
    while ($t_.Elapsed.TotalSeconds -lt 30) {
        Invoke-WebServer
        if ($Script:ReportServed -and -not $servedAt) { $servedAt = $t_.Elapsed.TotalSeconds }
        if ($servedAt -and ($t_.Elapsed.TotalSeconds - $servedAt) -ge 3) { break }
        Start-Sleep -Milliseconds 100
    }
    try { $Script:Listener.Stop(); $Script:Listener.Close() } catch {}
} else {
    Start-Process $Script:ReportHTML
}
