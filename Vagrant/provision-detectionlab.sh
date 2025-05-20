#!/bin/bash
# Shell Script - provision-detectionlab.sh

echo "🔄 Destruindo e criando VM: logger"
vagrant destroy -f logger
vagrant up logger --provision

echo "🔄 Destruindo e criando VM: dc"
vagrant destroy -f dc
vagrant up dc --provision

echo "🔄 Destruindo e criando VM: wef"
vagrant destroy -f wef
vagrant up wef --provision

echo "🔄 Destruindo e criando VM: win10"
vagrant destroy -f win10
vagrant up win10 --provision

echo "✅ Todas as VMs do DetectionLab foram provisionadas com sucesso."
