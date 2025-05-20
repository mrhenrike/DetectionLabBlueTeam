# PowerShell Script - provision-detectionlab.ps1
Write-Host "🔄 Destruindo e criando VM: logger"
vagrant destroy -f logger
vagrant up logger --provision

Write-Host "🔄 Destruindo e criando VM: dc"
vagrant destroy -f dc
vagrant up dc --provision

Write-Host "🔄 Destruindo e criando VM: wef"
vagrant destroy -f wef
vagrant up wef --provision

Write-Host "🔄 Destruindo e criando VM: win10"
vagrant destroy -f win10
vagrant up win10 --provision

Write-Host "✅ Todas as VMs do DetectionLab foram provisionadas com sucesso."
