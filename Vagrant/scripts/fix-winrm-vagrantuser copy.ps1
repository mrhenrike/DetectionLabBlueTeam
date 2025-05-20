function Log {
    param([string]$message)
    $timestamp = Get-Date -Format "HH:mm"
    Write-Host "[$timestamp] $message"
}

$timestamp = Get-Date -Format "HH:mm"
Write-Host "[$timestamp] Fixing WinRM and Vagrant user settings..."

# Ativa o PS Remoting e configura autenticação básica e sem criptografia
Enable-PSRemoting -Force
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Restart-Service winrm

# Desativa temporariamente a exigência de senha complexa
$timestamp = Get-Date -Format "HH:mm"
Write-Host "[$timestamp] Disabling password complexity temporarily..."
$cfg = "C:\secpol.cfg"
secedit /export /cfg $cfg
(Get-Content $cfg) -replace 'PasswordComplexity\s*=\s*1', 'PasswordComplexity = 0' | Set-Content $cfg
secedit /configure /db secedit.sdb /cfg $cfg /areas SECURITYPOLICY
Remove-Item $cfg -Force

# Cria ou ativa o usuário vagrant com senha simples
$timestamp = Get-Date -Format "HH:mm"
Write-Host "[$timestamp] Creating or enabling 'vagrant' user..."
net user vagrant vagrant /add
net user vagrant vagrant /active:yes

# Reativa política de complexidade de senha
$timestamp = Get-Date -Format "HH:mm"
Write-Host "[$timestamp] Restoring password complexity policy..."
$cfg = "C:\secpol.cfg"
secedit /export /cfg $cfg
(Get-Content $cfg) -replace 'PasswordComplexity\s*=\s*0', 'PasswordComplexity = 1' | Set-Content $cfg
secedit /configure /db secedit.sdb /cfg $cfg /areas SECURITYPOLICY
Remove-Item $cfg -Force

$timestamp = Get-Date -Format "HH:mm"
Write-Host "[$timestamp] WinRM and user setup complete!"
