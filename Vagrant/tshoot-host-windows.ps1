# tshoot-host-windows.ps1
Write-Host "[+] Starting Port and Process Troubleshooting..." -ForegroundColor Green

$portsToCheck = @(5985, 5986, 2222, 2249, 2250)
$occupiedPorts = @()

foreach ($port in $portsToCheck) {
    Write-Host "`n[*] Checking port $port..." -ForegroundColor Cyan
    $connections = netstat -ano | Select-String ":$port\s"

    if ($connections) {
        Write-Host "[!] Port $port is in use:" -ForegroundColor Yellow
        $connections | ForEach-Object {
            Write-Host "  $_"
            $connectionPid = ($_ -split '\s+')[-1]
            $occupiedPorts += $connectionPid
        }
    } else {
        Write-Host "[+] Port $port is free." -ForegroundColor Green
    }
}

if ($occupiedPorts.Count -gt 0) {
    Write-Host "`n[*] Listing processes occupying critical ports..." -ForegroundColor Cyan
    $uniquePids = $occupiedPorts | Select-Object -Unique
    foreach ($procId in $uniquePids) {
        try {
            $process = Get-Process -Id $procId -ErrorAction Stop
            Write-Host "PID $($procId): $($process.ProcessName)" -ForegroundColor Magenta
        } catch {
            Write-Host "PID $($procId): Process not found or terminated." -ForegroundColor DarkYellow
        }
    }
} else {
    Write-Host "`n[+] No critical ports occupied." -ForegroundColor Green
}

Write-Host "`n[*] Checking for VMware/Vagrant processes..." -ForegroundColor Cyan
Get-Process | Where-Object { $_.Name -match "vagrant|vmware" } | Format-Table -AutoSize

Write-Host "`n[*] Checking Firewall Rules for WinRM..." -ForegroundColor Cyan
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WinRM*" } | Format-Table -AutoSize

Write-Host "`n[*] Testing Localhost WinRM Ports..." -ForegroundColor Cyan
Test-NetConnection -ComputerName 127.0.0.1 -Port 5985
Test-NetConnection -ComputerName 127.0.0.1 -Port 5986

Write-Host "`n[+] Troubleshooting complete." -ForegroundColor Green
