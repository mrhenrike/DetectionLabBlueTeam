# fix-winrm.ps1 atualizado
function Log {
    param([string]$message)
    $timestamp = Get-Date -Format "HH:mm"
    Write-Host "[$timestamp] $message"
}

Log "Starting WinRM and basic setup..."

# Aguarda o serviço WinRM subir após restart
Write-Host "⌛ Aguardando WinRM responder na porta 5985..." -ForegroundColor Cyan

$Timeout = 60
$Counter = 0



# Habilita o PSRemoting e força o profile público
try {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Log "Enabled PSRemoting"
} catch {
    Log "Failed to enable PSRemoting: $_"
}

# Garante que o serviço WinRM está rodando
try {
    Set-Service winrm -StartupType Automatic
    Start-Service winrm
    Log "Started WinRM service"
} catch {
    Log "Failed to start WinRM service: $_"
}

# Permite requisições básicas e sem criptografia
try {
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force
    Log "Configured WinRM for Basic auth and unencrypted connections"
} catch {
    Log "Failed to configure WinRM settings: $_"
}

do {
    Start-Sleep -Seconds 3
    $Result = Test-NetConnection -ComputerName localhost -Port 5985
    $Counter += 3
} until ($Result.TcpTestSucceeded -or $Counter -ge $Timeout)

if ($Result.TcpTestSucceeded) {
    Write-Host "✅ WinRM está funcionando!" -ForegroundColor Green
} else {
    Write-Host "❌ WinRM não respondeu em $Timeout segundos. Pode ser necessário reiniciar manualmente." -ForegroundColor Red
}

Log "Finished fixing WinRM!"
