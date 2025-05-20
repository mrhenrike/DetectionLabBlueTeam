# Purpose: Installs osquery on the host. Osquery connects to Fleet via TLS.

Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Installing osquery..."
$flagfile = "C:\Program Files\osquery\osquery.flags"
$osqueryDir = "C:\Program Files\osquery"

# Ensure osquery directory exists
if (!(Test-Path $osqueryDir)) {
    Write-Host "[INFO] Creating osquery directory..."
    New-Item -ItemType Directory -Path $osqueryDir | Out-Null
}

# Install osquery silently via Chocolatey
choco install -y --limit-output --no-progress osquery | Out-String

# Check if the service is registered
$service = Get-WmiObject -Class Win32_Service -Filter "Name='osqueryd'"
if (-not $service) {
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Setting osquery to run as a service"
    New-Service -Name "osqueryd" -BinaryPathName "`"$osqueryDir\osqueryd\osqueryd.exe`" --flagfile=`"$flagfile`""
}

# Download the flags file (using TLS 1.2)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

if (-not (Test-Path $flagfile)) {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/palantir/osquery-configuration/master/Classic/Endpoints/Windows/osquery.flags" -OutFile $flagfile
}

# Add Fleet to hosts file if not present
if (-not (Select-String -Path "C:\Windows\System32\drivers\etc\hosts" -Pattern "fleet" -Quiet)) {
    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Adding Fleet to the hosts file"
    Add-Content "C:\Windows\System32\drivers\etc\hosts" "`t192.168.56.105`t fleet"
}

# Write the Fleet secret
$fleetSecretPath = "$osqueryDir\fleet_secret.txt"
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllLines($fleetSecretPath, "enrollmentsecretenrollmentsecret", $Utf8NoBomEncoding)

# Adjust contents of the flags file if it exists
if (Test-Path $flagfile) {
    (Get-Content $flagfile) -replace 'tls.endpoint.server.com', 'fleet:8412' |
        Set-Content $flagfile
    (Get-Content $flagfile) -replace 'path\\to\\file\\containing\\secret.txt', "$fleetSecretPath" |
        Set-Content $flagfile
    (Get-Content $flagfile) -replace 'c:\\ProgramData\\osquery\\certfile.crt', "$osqueryDir\certfile.crt" |
        Set-Content $flagfile
    (Get-Content $flagfile) -replace '--verbose=true', '--logger_min_status=1' |
        Set-Content $flagfile
}

# Copy certificate
$certSource = "C:\vagrant\resources\fleet\server.crt"
$certDest = "$osqueryDir\certfile.crt"
if (Test-Path $certSource) {
    Copy-Item $certSource $certDest -Force
} else {
    Write-Warning "Certificate file not found: $certSource"
}

# Try to start the osqueryd service
try {
    Start-Service osqueryd
    Write-Host "[OK] osqueryd service started successfully."
} catch {
    Write-Warning "Could not start osqueryd: $_"
}

# Final check
if ((Get-Service -Name osqueryd).Status -ne "Running") {
    Write-Warning "osqueryd service was not running after attempt. Please check logs manually."
}
