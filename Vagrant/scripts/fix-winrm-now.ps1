Write-Host "🔄 Reiniciando o serviço WinRM e aguardando ficar online..." -ForegroundColor Cyan

# Restart WinRM
Restart-Service WinRM -Force

# Aguarda até que o serviço esteja UP
$Timeout = 60
$Counter = 0

do {
    Start-Sleep -Seconds 3
    $Result = Test-NetConnection -ComputerName localhost -Port 5985
    Write-Host "⌛ Testando conexão WinRM na porta 5985... ($Counter s)"
    $Counter += 3
} until ($Result.TcpTestSucceeded -or $Counter -ge $Timeout)

if ($Result.TcpTestSucceeded) {
    Write-Host "✅ WinRM online! (porta 5985 respondendo)" -ForegroundColor Green
} else {
    Write-Host "❌ WinRM não respondeu em tempo hábil!" -ForegroundColor Red
}
