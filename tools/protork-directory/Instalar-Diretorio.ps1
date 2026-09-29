#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$directoryRoot = 'C:\ProgramData\ProtorkDirectory'
$nodePath = 'C:\Program Files\nodejs\node.exe'
$directoryTask = 'Protork-Diretorio'
$updateTask = 'Protork-Servidor-Atualizacoes'
$privateNetworks = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')

function Assert-PlainPath([string]$Path) {
    $cursor = $Path
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if (((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Caminho redirecionado nao permitido: $cursor"
            }
        }
        $parent = Split-Path -Path $cursor -Parent
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}
function Protect-Directory([string]$Path) {
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @('S-1-5-19','ReadAndExecute'))) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($entry[0]),
            [System.Security.AccessControl.FileSystemRights]$entry[1],
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Stop-TaskAndWait([string]$Name) {
    if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $Name
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-ScheduledTask -TaskName $Name).State -eq 'Running') {
            if ((Get-Date) -gt $deadline) { throw "Tarefa nao encerrou: $Name" }
            Start-Sleep -Milliseconds 300
        }
    }
}
try {
    if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress '192.168.1.95' -ErrorAction SilentlyContinue)) {
        throw 'Execute este arquivo NO SERVIDOR 192.168.1.95.'
    }
    foreach ($file in @($nodePath, "$PSScriptRoot\directory.mjs", "$PSScriptRoot\provision.mjs",
        'C:\ProgramData\ProtorkUpdates\server.mjs', 'C:\ProgramData\ProtorkUpdateSigning\private.pem')) {
        Assert-PlainPath $file
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Arquivo ausente: $file" }
    }
    if (-not (Get-ScheduledTask -TaskName $updateTask -ErrorAction SilentlyContinue)) { throw 'Tarefa do servidor de atualizacoes nao encontrada.' }
    Assert-PlainPath $directoryRoot
    if (Test-Path -LiteralPath $directoryRoot) {
        $owner = (Get-Acl -LiteralPath $directoryRoot).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18','S-1-5-32-544',[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {
            throw 'Diretorio preexistente pertence a outra conta. Nenhum arquivo foi alterado.'
        }
        foreach ($item in Get-ChildItem -LiteralPath $directoryRoot -Force -Recurse) { Assert-PlainPath $item.FullName }
    }
    Stop-TaskAndWait $directoryTask
    if (Get-NetTCPConnection -State Listen -LocalPort 8789 -ErrorAction SilentlyContinue) { throw 'Porta 8789 ocupada; nenhum processo foi encerrado.' }
    New-Item -ItemType Directory -Path $directoryRoot -Force | Out-Null
    Protect-Directory $directoryRoot
    foreach ($name in @('directory.mjs','provision.mjs')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $directoryRoot $name) -Force
    }
    $configPath = Join-Path $directoryRoot 'config.json'
    if (-not (Test-Path -LiteralPath $configPath)) {
        $rootCert = New-SelfSignedCertificate -Type Custom -Subject 'CN=Protork Directory Root' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -KeyUsage CertSign,CRLSign -TextExtension '2.5.29.19={critical}{text}ca=true&pathlength=0' -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddYears(5)
        $leafCert = New-SelfSignedCertificate -Type Custom -Subject 'CN=192.168.1.95' -Signer $rootCert -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable -KeyUsage DigitalSignature,KeyEncipherment -TextExtension @('2.5.29.17={text}IPAddress=192.168.1.95','2.5.29.37={text}1.3.6.1.5.5.7.3.1','2.5.29.19={critical}{text}ca=false') -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddYears(3)
        $random = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($random); $rng.Dispose()
        $passphrase = [Convert]::ToBase64String($random)
        $pfx = Join-Path $directoryRoot 'server.pfx'
        Export-PfxCertificate -Cert $leafCert -FilePath $pfx -Password (ConvertTo-SecureString $passphrase -AsPlainText -Force) -ChainOption EndEntityCertOnly | Out-Null
        Export-Certificate -Cert $rootCert -FilePath (Join-Path $directoryRoot 'root.cer') | Out-Null
        $config = @{ pfx = $pfx; passphrase = $passphrase } | ConvertTo-Json
        [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
        $passphrase = $null; $config = $null
    }
    foreach ($name in @('root.cer','server.pfx','config.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $directoryRoot $name) -PathType Leaf)) { throw "Instalacao incompleta: $name" }
    }
    # Only this brief restart touches the HTTP publication process, not remote sessions.
    Stop-TaskAndWait $updateTask
    try {
        & $nodePath (Join-Path $directoryRoot 'provision.mjs') prepare $directoryRoot
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao preparar certificado assinado.' }
    } finally { Start-ScheduledTask -TaskName $updateTask }
    $action = New-ScheduledTaskAction -Execute $nodePath -Argument ('"{0}" "{1}"' -f (Join-Path $directoryRoot 'directory.mjs'), $configPath) -WorkingDirectory $directoryRoot
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $directoryTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Usuarios Windows e IPs DHCP do Protork. Sem senhas de acesso remoto.' -Force | Out-Null
    foreach ($port in @(8788,8789)) {
        $rule = "Protork-Diretorio-Interno-$port"
        if (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue) {
            Set-NetFirewallRule -Name $rule -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort $port -LocalAddress '192.168.1.95' -RemoteAddress $privateNetworks -Program $nodePath
        } else {
            New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort $port -LocalAddress '192.168.1.95' -RemoteAddress $privateNetworks -Program $nodePath | Out-Null
        }
    }
    Start-ScheduledTask -TaskName $directoryTask
    $ready = $false
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        & $nodePath (Join-Path $directoryRoot 'provision.mjs') health $directoryRoot
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Diretorio registrado, mas HTTPS nao respondeu. Nao confirmado como ativo.' }
    $health = Invoke-WebRequest -UseBasicParsing -Uri 'http://192.168.1.95:8788/health' -TimeoutSec 5
    if ($health.Content.Trim() -ne 'Protork Updates OK') { throw 'Verificacao do servidor de atualizacoes falhou.' }
    $trust = Invoke-WebRequest -UseBasicParsing -Uri 'http://192.168.1.95:8788/updates/directory-trust.signed' -TimeoutSec 5
    if ($trust.StatusCode -ne 200) { throw 'Certificado assinado nao esta acessivel.' }
    Write-Host 'DIRETORIO INSTALADO E HTTPS VERIFICADO.' -ForegroundColor Green
    Write-Host 'Servidor pronto. As maquinas aparecerao ao receber o NOVO cliente com diretorio.'
    Write-Host 'Build30 e anteriores ainda nao enviam este cadastro. Nenhum MSI foi publicado por este script.'
} catch { Write-Host $_.Exception.Message -ForegroundColor Red }
Read-Host 'Pressione Enter para fechar'
