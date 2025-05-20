Write-Host ">>> Ajustando WinRM para usuário Vagrant..."

# Garante que o WinRM está rodando
$service = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($service.Status -ne 'Running') {
    Write-Host "WinRM não estava rodando. Iniciando serviço..."
    Start-Service WinRM
}

# Habilita as configurações necessárias
Write-Host "Configurando WSMan..."
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true -Force

# Cria regra de firewall para 5985/TCP se não existir
if (-not (Get-NetFirewallRule -DisplayName "Allow WinRM" -ErrorAction SilentlyContinue)) {
    Write-Host "Criando regra de firewall para WinRM (porta 5985)..."
    New-NetFirewallRule -DisplayName "Allow WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
} else {
    Write-Host "Regra de firewall para WinRM já existe."
}

# Adiciona o usuário Vagrant nas permissões
Write-Host "Configurando permissões de WinRM para o usuário vagrant..."
$Acl = Get-Acl WSMan:\localhost\Service\Auth
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("vagrant","FullControl","Allow")
$Acl.AddAccessRule($AccessRule)
Set-Acl WSMan:\localhost\Service\Auth $Acl

# Confirma se o serviço está OK
if ((Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue)) {
    Write-Host "WinRM está escutando na porta 5985!"
} else {
    Write-Host "⚠️ WinRM ainda não está escutando! Tentando reiniciar serviço..."
    Restart-Service WinRM -Force
    Start-Sleep -Seconds 5
}

Write-Host "✅ WinRM ajustado para usuário Vagrant com sucesso."
