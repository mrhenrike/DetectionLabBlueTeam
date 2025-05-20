#! /usr/bin/env bash
# shellcheck disable=SC1091,SC2129

# This is the script that is used to provision the logger host
START_TIME=$(date +%s)
set -euo pipefail
UBUNTU_VERSION=$(lsb_release -rs)
DNS_SERVER="8.8.8.8"
SUCCESS=()
WARNING=()
ERROR=()
FIXES=()

## Log stage
log_stage() {
  echo "$1"
}

# Função para checar a última vez que o cache do apt foi atualizado
check_last_apt_update() {
  log_stage "[*] Checking last apt-get update..."

  if [ ! -d /var/lib/apt/lists/ ]; then
    log_stage "[!] APT lists directory not found. Skipping check."
    return 1
  fi

  last_update_time=$(find /var/lib/apt/lists/ -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | awk '{print $1}')
  
  if [ -z "$last_update_time" ]; then
    log_stage "[!] No apt list files found to determine last update."
    return 1
  fi

  now=$(date +%s)
  diff_days=$(( (now - ${last_update_time%.*}) / 86400 ))

  last_update_human=$(date -d "@${last_update_time%.*}")

  log_stage "[+] Last apt-get update detected on: $last_update_human ($diff_days days ago)"

  if [ "$diff_days" -gt 7 ]; then
    log_stage "[!] It's been more than 7 days since last apt-get update!"
    return 1
  fi
  return 0
}

# Função para checar a última vez que o sistema foi atualizado via apt-get upgrade
check_last_apt_upgrade() {
  log_stage "[*] Checking last apt-get upgrade..."

  if [ ! -f /var/log/apt/history.log ]; then
    log_stage "[!] No apt history log found. Skipping check."
    return 1
  fi

  last_upgrade_time=$(grep -i "Start-Date" /var/log/apt/history.log | tail -1 | awk -F'Start-Date: ' '{print $2}')
  
  if [ -z "$last_upgrade_time" ]; then
    log_stage "[!] No upgrade history found."
    return 1
  fi

  # Converter para timestamp
  last_upgrade_epoch=$(date -d "$last_upgrade_time" +%s 2>/dev/null || echo "")

  if [ -z "$last_upgrade_epoch" ]; then
    log_stage "[!] Could not parse upgrade timestamp. Skipping."
    return 1
  fi

  now=$(date +%s)
  diff_days=$(( (now - last_upgrade_epoch) / 86400 ))

  log_stage "[+] Last apt-get upgrade detected on: $last_upgrade_time ($diff_days days ago)"

  if [ "$diff_days" -gt 30 ]; then
    log_stage "[!] It's been more than 30 days since last apt-get upgrade!"
    return 1
  fi
  return 0
}

update_system_and_install_dependencies() {
  echo ""
  echo "==========================================================================="
  echo " [*] Updating system and installing general dependencies..."
  echo "==========================================================================="

  if check_last_apt_update; then
    # Update apt sources
    log_stage "[*] Running apt-get update..."
    if apt-get update; then
        log_stage "[+] apt-get update completed successfully."
    else
        log_stage "[X] apt-get update failed. Proceeding anyway..."
    fi

    # Ensure apt-fast is installed
    log_stage "[*] Installing apt-fast if not already installed..."
    export APTFAST_CMD="apt-fast"
    if command -v apt-fast >/dev/null 2>&1; then
      log_stage "[+] apt-fast already installed."
    else
      apt-get install -y apt-fast || apt-get install -y apt
    fi
    
    if ! command -v apt-fast >/dev/null; then
      log_stage "[!] apt-fast unavailable. Using apt with fallback."
      APTFAST_CMD="apt"
    fi

    # Lista de dependências gerais
    GENERAL_DEPENDENCIES=(
        build-essential
        python3-pip
        htop
        unzip
        net-tools
        whois
        jq
        yq
        redis-server
        git
        dnsutils
        libssl-dev
    )

    # Instalação dos pacotes
    log_stage "[*] Installing general dependencies..."
    for package in "${GENERAL_DEPENDENCIES[@]}"; do
        if "${APTFAST_CMD}" install -y "$package"; then
            log_stage "[+] Successfully installed: $package"
        else
            log_stage "[!] Failed to install: $package. Continuing..."
        fi
    done

    log_stage "[+] Running apt-get clean..."
    apt-get clean

    log_stage "[+] Ensuring software-properties-common is installed..."
    "${APTFAST_CMD}" install -y software-properties-common

    if ! command -v snap >/dev/null; then
      log_stage "[+] Installing snapd..."
      "${APTFAST_CMD}" install -y snapd
    fi

    if [[ "$UBUNTU_VERSION" == "24.04" ]]; then
      systemctl is-active snapd.service >/dev/null 2>&1 || {
        log_stage "[*] Enabling snapd.service..."
        systemctl enable --now snapd
        sleep 3
      }
    fi

    log_stage "[+] Adding apt repositories..."

    # Adicionar o PPA do apt-fast apenas até Ubuntu 22.04
    if [[ "$UBUNTU_VERSION" =~ ^(18\.04|20\.04|22\.04)$ ]]; then
      if ! grep -q "apt-fast" /etc/apt/sources.list.d/* 2>/dev/null; then
        add-apt-repository -y -n ppa:apt-fast/stable
      fi
    else
      log_stage "[!] Skipping apt-fast PPA (not supported on Ubuntu $UBUNTU_VERSION)"
    fi

    # Adicionar o PPA do yq apenas até Ubuntu 22.04
    if [[ "$UBUNTU_VERSION" =~ ^(18\.04|20\.04|22\.04)$ ]]; then
      if ! grep -q "rmescandon" /etc/apt/sources.list.d/* 2>/dev/null; then
        add-apt-repository -y -n ppa:rmescandon/yq
      fi
    else
      log_stage "[!] Skipping yq PPA (not supported on Ubuntu $UBUNTU_VERSION). Will install via snap later if needed."
    fi

    # Adicionar o PPA do Suricata até Ubuntu 22.04
    if [[ "$UBUNTU_VERSION" =~ ^(18\.04|20\.04|22\.04)$ ]]; then
      if ! grep -q "oisf" /etc/apt/sources.list.d/* 2>/dev/null; then
        add-apt-repository -y -n ppa:oisf/suricata-stable
      fi
    else
      log_stage "[!] Skipping Suricata PPA (will install suricata from default repositories for Ubuntu $UBUNTU_VERSION)"
    fi

    log_stage "Using apt-fast to install base packages..."
    "${APTFAST_CMD}" install --no-install-recommends -y mysql-server libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin libossp-uuid-dev libavcodec-dev libavutil-dev libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libvncserver-dev libtelnet-dev libvorbis-dev libwebp-dev

    dpkg -s crudini >/dev/null 2>&1 || "${APTFAST_CMD}" install -y crudini

    # YQ se necessário instalar via snap para Ubuntu 24.04
    if ! command -v yq >/dev/null 2>&1; then
      if [[ "$UBUNTU_VERSION" == "24.04" ]]; then
        log_stage "[+] Installing yq via snap for Ubuntu 24.04..."
        snap install yq
        ln -sf /snap/bin/yq /usr/local/bin/yq
        log_stage "[!] Forcing daemon-reload after installation via snap..."
        systemctl daemon-reexec
        systemctl daemon-reload
      fi
    fi

    if ! yq --version 2>/dev/null | grep -q 'version 4'; then
      log_stage "[WARN] yq não é versão 4+. Verifique sintaxe dos comandos yq no script."
    fi

    # Instalar Tomcat9 se disponível, senão Tomcat10
    if apt-cache show tomcat9 &>/dev/null; then
      "${APTFAST_CMD}" install -y tomcat9 tomcat9-admin tomcat9-user tomcat9-common
    else
      "${APTFAST_CMD}" install -y tomcat10 tomcat10-admin tomcat10-user tomcat10-common
    fi

    log_stage "[+] Running apt-get clean..."
    apt-get clean
  else
    log_stage "Not needed update apt cache now."
  fi

  if check_last_apt_upgrade; then
    apt-get upgrade -y
  else 
    log_stage "Not needed upgrade the system now."
  fi 
}

## Install OpenVSwitch
install_openvswitch() {
  echo -e "\n==========================================================================="
  log_stage " [*] OpenVSwitch Installation..."
  echo -e "==========================================================================="

  if command -v ovsdb-server >/dev/null 2>&1; then
    log_stage "[*] Open vSwitch (OVS) already installed."
    SUCCESS+=("OVS is installed.")

    if systemctl is-active --quiet ovsdb-server.service; then
      log_stage "[*] OVS is running. Skipping installation"
    else
      log_stage "[X] OVS failed to start."
      WARNING+=("OVS is installed but not working.")
      FIXES+=("Try starting OVS manually: systemctl start ovsdb-server")
      return 1
    fi
    return 0

  else
    log_stage "[+] Installing and validating Open vSwitch (OVS)..."
    "${APTFAST_CMD}" install -y openvswitch-switch || {
      log_stage "[X] Failed to install openvswitch-switch package."
      ERROR+=("OVS failed is not installed.")
      FIXES+=("Try install OVS again manually: apt-get install -y openvswitch-switch")
      return 1
    }

    log_stage "[+] Enabling and starting Open vSwitch service..."
    systemctl enable openvswitch-switch
    systemctl start openvswitch-switch
    systemctl status openvswitch-switch
    
    if systemctl is-active --quiet ovsdb-server.service; then
      log_stage "[*] OVS was installed with success."
      SUCCESS+=("OVS is OK.")
    else
      log_stage "[X] OVS failed to start."
      WARNING+=("OVS is installed but not working.")
      FIXES+=("Try starting OVS manually: systemctl start ovsdb-server")
      return 1
    fi

  fi
  
  sleep 2

  log_stage "[+] Checking if ovsdb-server process is running..."
  if ! pgrep -f ovsdb-server >/dev/null 2>&1; then
    log_stage "[!] ovsdb-server process not found. Attempting to restart service..."
    systemctl restart openvswitch-switch
    sleep 2
    if ! pgrep -f ovsdb-server >/dev/null 2>&1; then
      log_stage "[X] ovsdb-server failed to start even after restart."
      WARNING+=("OVS is installed but not working.")
      FIXES+=("Try starting OVS manually: systemctl start ovsdb-server")
      return 1
    fi
  fi

  log_stage "[+] Validating OVSDB operations with ovs-vsctl..."
  if ! ovs-vsctl show >/dev/null 2>&1; then
    log_stage "[X] ovs-vsctl test failed. OVS may not be properly configured."
    WARNING+=("OVS may not be properly configured.")
    FIXES+=("Try to reconfigure or to install OVS again.")
    return 1
  fi

  log_stage "[+] Open vSwitch installed, running, and operational!"
}

## Splunk Variables
config_variables_splunk(){
  log_stage "[*] Configuring variables for Splunk and Zeek Servers..."
  SPLUNK_AUTH='admin:changeme'
  SPLUNK_PATH="/opt/splunk"
  ZEEK_PATH="/opt/zeek"
  exec > >(tee -a /var/log/logger_provision.log) 2>&1

  # Source variables from logger_variables.sh
  source /vagrant/logger_variables.sh 2>/dev/null || source /home/vagrant/logger_variables.sh 2>/dev/null || log_stage "Unable to locate logger_variables.sh"

  if [ -z "$MAXMIND_LICENSE" ]; then
    log_stage "Note: You have not entered a MaxMind API key in logger_variables.sh, so the ASNgen Splunk app may not work correctly."
    log_stage "However, it is optional and everything else should function correctly."
  fi

  export DEBIAN_FRONTEND=noninteractive
  echo "apt-fast apt-fast/maxdownloads string 10" | debconf-set-selections
  echo "apt-fast apt-fast/dlflag boolean true" | debconf-set-selections
}

## Fixing DNS
fixing_DNS(){
  echo -e "\n==========================================================================="
  log_stage " [*] Override existing DNS settings using netplan..."
  echo -e "==========================================================================="

  # Override existing DNS Settings using netplan, but don't do it for Terraform AWS builds
  if ! curl -s 169.254.169.254 --connect-timeout 2 >/dev/null; then
    echo -e "    eth1:\n      dhcp4: true\n      nameservers:\n        addresses: [8.8.8.8,8.8.4.4]" >> /etc/netplan/01-netcfg.yaml
    netplan apply
  fi

  # Kill systemd-resolvd, just use plain ol' /etc/resolv.conf
  systemctl disable systemd-resolved
  systemctl stop systemd-resolved
  rm /etc/resolv.conf
  echo 'nameserver 8.8.8.8' >> /etc/resolv.conf
  echo 'nameserver 8.8.4.4' >> /etc/resolv.conf
  echo 'nameserver 192.168.56.102' >> /etc/resolv.conf
}

## Modify MOTD
modify_motd() {
  echo -e "\n==========================================================================="
  log_stage " [*] Adjusting MOTD..."
  echo -e "==========================================================================="  
  
  log_stage "[+] Updating the MOTD..."
  # Force color terminal
  sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/g' /root/.bashrc
  sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/g' /home/vagrant/.bashrc
  # Remove some stock Ubuntu MOTD content
  chmod -x /etc/update-motd.d/10-help-text
  # Copy the DetectionLab MOTD
  [ -f /etc/update-motd.d/20-detectionlab ] || cp /vagrant/resources/logger/20-detectionlab /etc/update-motd.d/
  chmod +x /etc/update-motd.d/20-detectionlab
}

## Fix ETH1 Static IP
fix_eth1_static_ip() {
  echo -e "\n==========================================================================="
  log_stage " [*] Fixing Static IP for eth1 interface..."
  echo -e "==========================================================================="

  chmod 600 /etc/netplan/*.yaml 2>/dev/null 
  chown root:root /etc/netplan/*.yaml 

  USING_KVM=$(sudo lsmod | grep kvm)
  if [ -n "$USING_KVM" ]; then
    log_stage "[!] Using KVM, no need to fix DHCP for eth1 iface"
    return 0
  fi
  if [ -f /sys/class/net/eth2/address ]; then
    if [ "$(cat /sys/class/net/eth2/address)" == "00:50:56:a3:b1:c4" ]; then
      log_stage "[!] Using ESXi, no need to change anything"
      return 0
    fi
  fi
  # TODO: try to set correctly directly through vagrant net config
  netplan set --origin-hint 90-disable-eth1-dhcp ethernets.eth1.dhcp4=false
  netplan apply

  # Fix eth1 if the IP isn't set correctly
  ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
  if [ "$ETH1_IP" != "192.168.56.105" ]; then
    log_stage "[X] Incorrect IP Address settings detected. Attempting to fix."
    ip link set dev eth1 down
    ip addr flush dev eth1
    ip link set dev eth1 up
    counter=0
    while :; do
      ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
      if [ "$ETH1_IP" == "192.168.56.105" ]; then
        log_stage "[*] The static IP has been fixed and set to 192.168.56.105"
        break
      else
        if [ $counter -le 20 ]; then
          ((counter++))
          log_stage "[!] Waiting for IP $counter/20 seconds"
          sleep 1
          continue
        else
          log_stage "[X] Failed to fix the broken static IP for eth1. Exiting because this will cause problems with other VMs."
          log_stage "[X] eth1's current IP address is $ETH1_IP"
          exit 1
        fi
      fi
    done
  fi

  # Make sure we do have a DNS resolution
  "${APTFAST_CMD}" install -y dnsutils
  while true; do
    if [ "$(dig +short @8.8.8.8 github.com)" ]; then break; fi
    sleep 1
  done
}

## Check and Fix Splunk Certs and Users
fix_splunk_ssl_and_admin() {
  echo "[*] Corrigindo certificados SSL do Splunk e criando usuário admin padrão..."

  SPLUNK_BIN="/opt/splunk/bin/splunk"
  SPLUNK_DIR="/opt/splunk/etc/auth"
  ADMIN_USER="admin"
  ADMIN_PASS="changeme"

  # 1. Para o Splunk se estiver rodando
  $SPLUNK_BIN stop || true

  # 2. Remove antigos certificados problemáticos
  echo "[*] Limpando certificados antigos..."
  rm -f "$SPLUNK_DIR"/ca.* "$SPLUNK_DIR"/cacert.pem "$SPLUNK_DIR"/server.*

  # 3. Gera nova CA
  echo "[*] Gerando nova CA..."
  openssl genrsa -out "$SPLUNK_DIR/ca.key.pem" 2048
  openssl req -x509 -new -nodes -key "$SPLUNK_DIR/ca.key.pem" -sha256 -days 3650 -out "$SPLUNK_DIR/ca.pem" -subj "/CN=Logger-CA"
  cp "$SPLUNK_DIR/ca.pem" "$SPLUNK_DIR/cacert.pem"

  # 4. Gera novo certificado de servidor
  echo "[*] Gerando novo certificado do servidor..."
  openssl genrsa -out "$SPLUNK_DIR/server.key.pem" 2048
  openssl req -new -key "$SPLUNK_DIR/server.key.pem" -out "$SPLUNK_DIR/server.csr.pem" -subj "/CN=logger"
  openssl x509 -req -in "$SPLUNK_DIR/server.csr.pem" -CA "$SPLUNK_DIR/cacert.pem" -CAkey "$SPLUNK_DIR/ca.key.pem" -CAcreateserial -out "$SPLUNK_DIR/server.cert.pem" -days 3650 -sha256

  # 5. Junta cert + key em server.pem
  cat "$SPLUNK_DIR/server.cert.pem" "$SPLUNK_DIR/server.key.pem" > "$SPLUNK_DIR/server.pem"

  # 6. Inicia o Splunk novamente
  echo "[*] Reiniciando o Splunk..."
  $SPLUNK_BIN start --accept-license --answer-yes --no-prompt --seed-passwd "$ADMIN_PASS"

  sleep 10

  # 7. Verifica se o Splunk está rodando
  if ! $SPLUNK_BIN status | grep -q "splunkd is running"; then
    echo "[X] Splunk não iniciou corretamente. Abortando."
    return 1
  fi

  echo "[*] Verificando API de Management (8089)..."
  if curl -sk https://127.0.0.1:8089/services/server/info | grep -q "Unauthorized"; then
    echo "[*] Nenhum usuário configurado. Vamos criar o admin ($ADMIN_USER)..."

    # 8. Cria admin manualmente se necessário
    $SPLUNK_BIN add user "$ADMIN_USER" -password "$ADMIN_PASS" -role admin <<EOF
$ADMIN_USER
$ADMIN_PASS
EOF

    sleep 5
    $SPLUNK_BIN restart
  fi

  sleep 10

  # 9. Validação Final
  echo "[*] Validando acesso final à API..."
  if curl -sku "$ADMIN_USER:$ADMIN_PASS" https://127.0.0.1:8089/services/server/info | grep -q "<title>server-info</title>"; then
    echo "[✅] Splunk configurado com sucesso! Admin: $ADMIN_USER / Senha: $ADMIN_PASS"
  else
    echo "[X] Houve um problema finalizando a configuração. Verifique os logs."
    return 1
  fi
}

## Install SPLUNK SIEM
install_splunk() {
  echo -e "\n==========================================================================="
  log_stage " [*] SPLUK SIEM installation..."
  echo -e "==========================================================================="
  
  config_variables_splunk

  # Check if Splunk is already installed
  if [ -f "/opt/splunk/bin/splunk" ] || command -v splunk &>/dev/null; then
    log_stage "[*] Splunk SIEM already installed."

    if systemctl is-active --quiet splunkd; then
      log_stage "[*] Splunk is running. Skipping installation."
      SUCCESS+=("Splunk is installed.")
    else
      log_stage "[X] Splunk failed to start."
      WARNING+=("Splunk is installed but is NOT running (may require manual start).")
      FIXES+=("Try starting Splunk manually: 'systemctl start splunkd' OR '/opt/splunk/bin/splunk start'")
      return 1
    fi
    return 0

  else
    log_stage "[+] Installing Splunk..."
    cd /opt

    # Prime DNS cache to avoid flaky wget failures
    for domain in download.splunk.com splunk.com www.splunk.com; do
      dig @$DNS_SERVER "$domain" >/dev/null 2>&1 || true
    done

    # Try to resolve latest Splunk version
    log_stage "[+] Attempting to autoresolve the latest version of Splunk..."
    LATEST_SPLUNK=$(curl -fsSL https://www.splunk.com/en_us/download/splunk-enterprise.html | \
      grep -oP 'https://download\.splunk\.com[^\"]+\.deb' | head -n1)

    if [[ "$LATEST_SPLUNK" =~ \.deb$ ]]; then
      log_stage "[+] Resolved latest Splunk URL: $LATEST_SPLUNK"
      SPLUNK_FILENAME="/opt/$(basename "$LATEST_SPLUNK")"
      wget --progress=bar:force -O "$SPLUNK_FILENAME" "$LATEST_SPLUNK"
    else
      log_stage "[X] Auto-resolve failed. Falling back to hardcoded URL..."
      SPLUNK_FILENAME="/opt/splunk-9.4.1-e3bdab203ac8-linux-amd64.deb"
      wget --progress=bar:force -O "$SPLUNK_FILENAME" "https://download.splunk.com/products/splunk/releases/9.4.1/linux/splunk-9.4.1-e3bdab203ac8-linux-amd64.deb"
    fi

    # Validate the .deb file
    if [[ "$SPLUNK_FILENAME" =~ splunk-[0-9]+\.[0-9]+\.[0-9]+.*\.deb$ ]]; then
      log_stage "[+] Splunk file valid detected."
    else
      log_stage "[X] Invalid Splunk file. Aborting."
      ERROR+=("Splunk DEB invalid.")
      FIXES+=("Try downloading and installing Splunk manually.")
      return 1
    fi

    # Install Splunk
    if [ -f "$SPLUNK_FILENAME" ]; then
      log_stage "Installing $SPLUNK_FILENAME..."
      dpkg -i "$SPLUNK_FILENAME"
      /opt/splunk/bin/splunk enable boot-start --accept-license --answer-yes --no-prompt --seed-passwd changeme
      /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
      /opt/splunk/bin/splunk status

      if command -v splunk >/dev/null; then
        log_stage "[X] Splunk installation failed. Exiting."
        ERROR+=("Splunk failed during installation.")
        FIXES+=("Check .deb file and reinstall manually.")
        return 1
      else
        log_stage "[*] Splunk was installed with success."
        SUCCESS+=("Splunk is installed.")
      fi
    else
      log_stage "[X] Splunk .deb file not found. Exiting."
      ERROR+=("Splunk DEB not found.")
      FIXES+=("Try installing Splunk manually.")
      return 1
    fi

    # Create symlink
    ln -sf /opt/splunk/bin/splunk /usr/local/bin/splunk

    # Verify if admin user exists, otherwise seed password
    log_stage "Checking if Splunk is initialized..."
    if curl -sku admin:changeme https://127.0.0.1:8089/services/server/info | grep -q "<title>server-info</title>"; then
      log_stage "[+] Splunk already initialized with admin user."
    else
      log_stage "[*] Initializing Splunk with default admin password 'changeme'..."
      /opt/splunk/bin/splunk stop || true
      /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
    fi

    # Confirm if Splunk is ready
    for i in {1..90}; do
      if curl -sku admin:changeme https://127.0.0.1:8089/services/server/info | grep -q "<title>server-info</title>"; then
        log_stage "[+] Splunk daemon and API are ready."
        break
      fi
      sleep 2
    done

    /opt/splunk/bin/splunk add index wineventlog -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index osquery -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index osquery-status -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index sysmon -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index powershell -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index zeek -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index suricata -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index threathunting -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index evtx_attack_samples -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk add index msexchange -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_forwarder/splunk-add-on-for-microsoft-windows_700.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/splunk-add-on-for-microsoft-sysmon_1062.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/asn-lookup-generator_110.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/lookup-file-editor_331.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/splunk-add-on-for-zeek-aka-bro_400.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/force-directed-app-for-splunk_200.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/punchcard-custom-visualization_130.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/sankey-diagram-custom-visualization_130.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/link-analysis-app-for-splunk_161.tgz -auth "$SPLUNK_AUTH"
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/threathunting_1492.tgz -auth "$SPLUNK_AUTH"

    # Fix ASNGen App - https://github.com/doksu/TA-asngen/issues/18#issuecomment-685691630
    echo 'python.version = python2' >>/opt/splunk/etc/apps/TA-asngen/default/commands.conf

    # Install the Maxmind license key for the ASNgen App if it was provided
    if [ -n "$MAXMIND_LICENSE" ]; then
      mkdir -p /opt/splunk/etc/apps/TA-asngen/local
      [ -f /opt/splunk/etc/apps/TA-asngen/local/asngen.conf ] || cp /opt/splunk/etc/apps/TA-asngen/default/asngen.conf /opt/splunk/etc/apps/TA-asngen/local/asngen.conf
      sed -i "s/license_key =/license_key = $MAXMIND_LICENSE/g" /opt/splunk/etc/apps/TA-asngen/local/asngen.conf
    fi

    # Install a Splunk license if it was provided
    if [ -n "$BASE64_ENCODED_SPLUNK_LICENSE" ]; then
      echo "$BASE64_ENCODED_SPLUNK_LICENSE" | base64 -d >/tmp/Splunk.License
      /opt/splunk/bin/splunk add licenses /tmp/Splunk.License -auth "$SPLUNK_AUTH"
      rm /tmp/Splunk.License
    fi

    # Replace the props.conf for Sysmon TA and Windows TA
    # Removed all the 'rename = xmlwineventlog' directives
    # I know youre not supposed to modify files in "default",
    # but for some reason adding them to "local" wasnt working
    [ -f /opt/splunk/etc/apps/Splunk_TA_windows/default/props.conf ] || cp /vagrant/resources/splunk_server/windows_ta_props.conf /opt/splunk/etc/apps/Splunk_TA_windows/default/props.conf
    [ -f /opt/splunk/etc/apps/TA-microsoft-sysmon/default/props.conf ] || cp /vagrant/resources/splunk_server/sysmon_ta_props.conf /opt/splunk/etc/apps/TA-microsoft-sysmon/default/props.conf

    # Add props.conf to Splunk Zeek TA to properly parse timestamp
    # and avoid grouping events as a single event
    mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local && cp /vagrant/resources/splunk_server/zeek_ta_props.conf /opt/splunk/etc/apps/Splunk_TA_bro/local/props.conf

    # Add custom Macro definitions for ThreatHunting App
    [ -f /opt/splunk/etc/apps/ThreatHunting/default/macros.conf ] || cp /vagrant/resources/splunk_server/macros.conf /opt/splunk/etc/apps/ThreatHunting/default/macros.conf
    
    # Fix some misc stuff
    sed -i 's/index=windows/`windows`/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
    sed -i 's/$host$)/$host$*)/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
    
    # This is probably horrible and may break some stuff, but I'm hoping it fixes more than it breaks
    find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/host_fqdn/ComputerName/g' {} \;
    find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/event_id/EventCode/g' {} \;

    # Fix Windows TA macros
    mkdir -p /opt/splunk/etc/apps/Splunk_TA_windows/local
    [ -f /opt/splunk/etc/apps/Splunk_TA_windows/local/macros.conf ] || cp /opt/splunk/etc/apps/Splunk_TA_windows/default/macros.conf /opt/splunk/etc/apps/Splunk_TA_windows/local
    sed -i 's/wineventlog_windows/wineventlog/g' /opt/splunk/etc/apps/Splunk_TA_windows/local/macros.conf
    
    # Fix Force Directed App until 2.0.1 is released (https://answers.splunk.com/answers/668959/invalid-key-in-stanza-default-value-light.html#answer-669418)
    rm /opt/splunk/etc/apps/force_directed_viz/default/savedsearches.conf

    # Add a Splunk TCP input on port 9997
    echo -e "[splunktcp://9997]\nconnection_host = ip" >/opt/splunk/etc/apps/search/local/inputs.conf
    # Add props.conf and transforms.conf
    [ -f /opt/splunk/etc/apps/search/local/props.conf  ] || cp /vagrant/resources/splunk_server/props.conf /opt/splunk/etc/apps/search/local/
    [ -f /opt/splunk/etc/apps/search/local/transforms.conf ] || cp /vagrant/resources/splunk_server/transforms.conf /opt/splunk/etc/apps/search/local/
    [ -f /opt/splunk/etc/system/local/limits.conf ] || cp /opt/splunk/etc/system/default/limits.conf /opt/splunk/etc/system/local/limits.conf
    
    # Bump the memtable limits to allow for the ASN lookup table
    sed -i.bak 's/max_memtable_bytes = 10000000/max_memtable_bytes = 30000000/g' /opt/splunk/etc/system/local/limits.conf

    # Skip Splunk Tour and Change Password Dialog
    log_stage "[-] Disabling the Splunk tour prompt..."
    touch /opt/splunk/etc/.ui_login
    mkdir -p /opt/splunk/etc/users/admin/search/local
    echo -e "[search-tour]\nviewed = 1" >/opt/splunk/etc/system/local/ui-tour.conf
    
    # Source: https://answers.splunk.com/answers/660728/how-to-disable-the-modal-pop-up-help-us-to-improve.html
    if [ ! -d "/opt/splunk/etc/users/admin/user-prefs/local" ]; then
      mkdir -p "/opt/splunk/etc/users/admin/user-prefs/local"
    fi
    echo '[general]
render_version_messages = 1
dismissedInstrumentationOptInVersion = 4
notification_python_3_impact = false
display.page.home.dashboardId = /servicesNS/nobody/search/data/ui/views/logger_dashboard' >/opt/splunk/etc/users/admin/user-prefs/local/user-prefs.conf
    # Enable SSL Login for Splunk
    echo -e "[settings]\nenableSplunkWebSSL = true" >/opt/splunk/etc/system/local/web.conf
    
    # Copy over the Logger Dashboard
    if [ ! -d "/opt/splunk/etc/apps/search/local/data/ui/views" ]; then
      mkdir -p "/opt/splunk/etc/apps/search/local/data/ui/views"
    fi
    cp /vagrant/resources/splunk_server/logger_dashboard.xml /opt/splunk/etc/apps/search/local/data/ui/views || echo "Unable to find dashboard"
    
    # Reboot Splunk to make changes take effect
    /opt/splunk/bin/splunk restart
    /opt/splunk/bin/splunk enable boot-start
  fi
  
  # Include Splunk and Zeek in the PATH
  grep -q 'SPLUNK_HOME' ~/.bashrc || echo "export SPLUNK_HOME=/opt/splunk" >> ~/.bashrc
  grep -q '/opt/splunk/bin' ~/.bashrc || echo 'export PATH="$PATH:/opt/splunk/bin:/opt/zeek/bin"' >> ~/.bashrc
}

## Palantir OSQuery Cofig
download_palantir_osquery_config() {
  echo -e "\n==========================================================================="
  log_stage " [*] OS Query Configs..."
  echo -e "==========================================================================="

  if [ -d "/opt/osquery-configuration" ]; then
    log_stage "[+] OS Query configs have already been downloaded. Skipping this step."
    return 0
  else
    log_stage "[+] Downloading Palantir osquery configs..."
    cd /opt
    git clone https://github.com/palantir/osquery-configuration.git
    log_stage "[!] Download completed with success."
  fi
}


## Install Fleet
install_fleet_import_osquery_config() {
  echo -e "\n==========================================================================="
  log_stage " [*] Fleet Server Installation..."
  echo -e "==========================================================================="

  if [ -d "/opt/fleet" ]; then
    log_stage "[+] Fleet directory exist. Checking services."
    
    if [ -f /etc/systemd/system/fleet.service ] && systemctl is-active --quiet fleet; then
      log_stage "[*] Fleet is already installed and running. Skipping installation."
      SUCCESS+=("Fleet is installed.")
    else
      log_stage "[X] Fleet service isn't running. Please check this service manually as soon as possible."
      WARNING+=("Fleet service is NOT running.")
      FIXES+=("Please check Fleet service manually as soon as possible.")
      return 1
    fi
    
    if [ -f /etc/systemd/system/fleetctl.service ] && systemctl is-active --quiet fleetctl; then
      log_stage "[*] Fleetclt is already installed and running. Skipping installation."
      SUCCESS+=("Fleetctl is installed.")
    else
      log_stage "[X] Fleetctl service isn't running. Please check this service manually as soon as possible."
      WARNING+=("Fleetctl service is NOT running.")
      FIXES+=("Please check Fleetctl service manually as soon as possible.")
      return 1
    fi
    return 0

  else
    log_stage "[+] Installing Fleet..."
    if [ ! -d "/opt/fleet" ]; then
        mkdir -p "/opt/fleet"
    fi
    cd /opt/fleet
    
    # Always download the latest release of Fleet and Fleetctl
    curl -s https://api.github.com/repos/fleetdm/fleet/releases/latest | jq '.assets[] | select(.name|match("linux.*.tar.gz$")) | .browser_download_url' | sed 's/"//g' | grep fleetctl | grep amd64 | wget --progress=bar:force -i -
    curl -s https://api.github.com/repos/fleetdm/fleet/releases/latest | jq '.assets[] | select(.name|match("linux.*.tar.gz$")) | .browser_download_url' | sed 's/"//g' | grep fleet | grep -v fleetctl | wget --progress=bar:force -i -
    
    tar -xf fleet_*.tar.gz
    tar -xf fleetctl_*.tar.gz

    cp -f fleetctl_*/fleetctl /usr/local/bin/fleetctl && chmod +x /usr/local/bin/fleetctl
    cp -f fleet_*/fleet /usr/local/bin/fleet && chmod +x /usr/local/bin/fleet

    if ! command -v fleetctl &>/dev/null; then
      log_stage "[X] fleetctl failed to install. Aborting..."
      ERROR+=("Fleetctl failed in the installation process.")
      return 1
    fi

    if ! command -v fleet &>/dev/null; then
      log_stage "[X] fleet failed to install. Aborting..."
      ERROR+=("Fleet failed in the installation process.")
      return 1
    fi

    ## Add hosts entry
    if ! grep 'fleet' /etc/hosts; then
      echo -e "\n127.0.0.1       fleet" >>/etc/hosts
    fi
    if ! grep 'logger' /etc/hosts; then
      echo -e "\n127.0.0.1       logger" >>/etc/hosts
    fi

    # Set MySQL username and password, create fleet database
    mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'fleet';"
    mysql -uroot -pfleet -e "create database fleet;"

    # Prepare the DB
    fleet prepare db --mysql_address=127.0.0.1:3306 --mysql_database=fleet --mysql_username=root --mysql_password=fleet

    # Copy over the certs and service file
    cp -f /vagrant/resources/fleet/server.* /opt/fleet/
    [ -f /etc/systemd/system/fleet.service ] || cp /vagrant/resources/fleet/fleet.service /etc/systemd/system/fleet.service

    # Create directory for logs
    mkdir -p /var/log/fleet

    # Install the service file
    systemctl daemon-reload
    systemctl enable fleet.service
    systemctl start fleet.service
    systemctl status fleet.service
    systemctl is-active --quiet fleet || { log_stage "[X] Fleet failed to start."; return 1; }

    # Start Fleet
    # log_stage "[!] Waiting for fleet service to start..."
    # while true; do
    #   result=$(curl --silent -k https://127.0.0.1:8412/setup)
    #   if echo "$result" | grep -q setup; then break; fi
    #   sleep 5
    # done

    # log_stage "[!] Waiting for fleet service to be healthy..."

    # until curl -sk https://127.0.0.1:8412/healthz | grep -q healthy; do
    #   sleep 5
    # done

    # log_stage "[+] Fleet service is healthy. Proceeding with setup..."

    fleetctl config set --address https://192.168.56.105:8412
    fleetctl config set --tls-skip-verify true

    if ! fleetctl config get | grep -q 'https://'; then
      fleetctl setup --email admin@detectionlab.network --name admin --password 'Fl33tpassword!' --org-name DetectionLab
    fi
    fleetctl login --email admin@detectionlab.network --password 'Fl33tpassword!'

    # Set the enrollment secret to match what we deploy to Windows hosts
    if mysql -uroot --password=fleet -e 'use fleet; INSERT INTO enroll_secrets(created_at, secret, team_id) VALUES ("2022-05-30 21:20:23", "enrollmentsecretenrollmentsecret", NULL);'; then
      log_stage "[+] Updated enrollment secret"
    else
      log_stage "[X] Error adding the custom enrollment secret. This is going to cause problems with agent enrollment."
    fi

    # Change the query invervals to reflect a lab environment
    # Every hour -> Every 3 minutes
    # Every 24 hours -> Every 15 minutes
    if ! fleetctl get queries | grep -q "Scheduled"; then
      fleetctl apply -f /opt/osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    fi

    sed -i 's/interval: 3600/interval: 300/g' /opt/osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 3600/interval: 300/g' /opt/osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    sed -i 's/interval: 28800/interval: 1800/g' /opt/osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 28800/interval: 1800/g' /opt/osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    sed -i 's/interval: 0/interval: 1800/g' /opt/osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 0/interval: 1800/g' /opt/osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml

    # Don't log osquery INFO messages
    # Fix snapshot event formatting
    fleetctl get config >/tmp/config.yaml
    /usr/bin/yq eval -i '.spec.agent_options.config.options.enroll_secret = "enrollmentsecretenrollmentsecret"' /tmp/config.yaml
    /usr/bin/yq eval -i '.spec.agent_options.config.options.logger_snapshot_event_type = true' /tmp/config.yaml
    fleetctl apply -f /tmp/config.yaml

    # Use fleetctl to import YAML files
    fleetctl apply -f /opt/osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    fleetctl apply -f /opt/osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    for pack in /opt/osquery-configuration/Fleet/Endpoints/packs/*.yaml; do
      fleetctl apply -f "$pack"
    done

    # Add Splunk monitors for Fleet
    # Files must exist before splunk will add a monitor
    touch /var/log/fleet/osquery_result
    touch /var/log/fleet/osquery_status
  fi
}

## Install Zeek
install_zeek() {
  echo -e "\n==========================================================================="
  log_stage " [*] ZEEK Server Installation..."
  echo -e "==========================================================================="
  
  if [ -f /opt/zeek/bin/zeek ] || [ -f /etc/systemd/system/zeek.service ]; then
    log_stage "[*] Zeek already installed."

    if systemctl is-active --quiet zeek; then
      log_stage "[X] Zeek service isn't running. Please check this service manually as soon as possible."
      WARNING+=("Zeek service is NOT running.")
      FIXES+=("Please check Zeek service manually as soon as possible.")
      return 1
    fi
    log_stage "[*] Zeek service is running. Skipping installation."
    SUCCESS+=("Zeek is installed.")
    return 0
  
  else
    log_stage "[+] Installing Zeek..."
    NODECFG=/opt/zeek/etc/node.cfg

    case "$UBUNTU_VERSION" in
      18.04|20.04)
        log_stage "[+] Detected Ubuntu $UBUNTU_VERSION. Installing Zeek via APT (zeek-lts)..."
        
        echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.asc] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/ /" > /etc/apt/sources.list.d/zeek.list
        curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/Release.key" -o /usr/share/keyrings/zeek-archive-keyring.asc
        
        apt-get update
        apt-get install -y zeek-lts
        ;;
      22.04|24.04)
        log_stage "[+] Detected Ubuntu $UBUNTU_VERSION. Installing Zeek manually (build from tar.gz)..."
        
        cd /opt
        wget --progress=bar:force https://download.zeek.org/zeek-6.0.3.tar.gz
        tar -xzf zeek-6.0.3.tar.gz
        cd zeek-6.0.3

        ./configure --prefix=/opt/zeek
        make -j"$(nproc)"
        make install

        ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
        ;;
      *)
        log_stage "[X] Ubuntu version $UBUNTU_VERSION not supported for automatic Zeek installation."
        ERROR+=("Zeek was NOT installed because Ubuntu version not supported.")
        exit 1
        ;;
    esac

    log_stage "[+] Configuring Zeek basic setup..."
    mkdir -p /opt/zeek/etc
    mkdir -p /opt/zeek/logs
    mkdir -p /opt/zeek/spool
 
    # Adiciona Zeek no PATH na sessão atual (sem depender do .bashrc)
    export PATH=$PATH:/opt/zeek/bin

    pip3 install zkg==2.1.1
    sed -i 's/isAlive()/is_alive()/g' /usr/local/bin/zkg

    zkg refresh
    zkg autoconfig
    zkg install --force salesforce/ja3

    # Cria o local.zeek com os módulos desejados
    cat <<EOF >/opt/zeek/share/zeek/site/local.zeek
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load tuning/json-logs
@load policy/integration/collective-intel
@load policy/frameworks/intel/do_notice
@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/files/hash-all-files
@load base/protocols/smb
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load ja3

redef Intel::read_files += {
  "/opt/zeek/etc/intel.dat"
};

redef ignore_checksums = T;
EOF

    mkdir -p /opt/splunk/etc/apps/search/local
    touch /opt/splunk/etc/apps/search/local/inputs.conf

    # Configura node.cfg
    crudini --del $NODECFG zeek
    crudini --set $NODECFG manager type manager
    crudini --set $NODECFG manager host localhost
    crudini --set $NODECFG proxy type proxy
    crudini --set $NODECFG proxy host localhost

    # Interface ETH0 (apenas se não for AWS)
    if ! curl -s 169.254.169.254 --connect-timeout 2 >/dev/null; then
      crudini --set $NODECFG worker-eth0 type worker
      crudini --set $NODECFG worker-eth0 host localhost
      crudini --set $NODECFG worker-eth0 interface eth0
      crudini --set $NODECFG worker-eth0 lb_method pf_ring
      crudini --set $NODECFG worker-eth0 lb_procs "$(nproc)"
    fi

    # Interface ETH1 (sempre configura)
    crudini --set $NODECFG worker-eth1 type worker
    crudini --set $NODECFG worker-eth1 host localhost
    crudini --set $NODECFG worker-eth1 interface eth1
    crudini --set $NODECFG worker-eth1 lb_method pf_ring
    crudini --set $NODECFG worker-eth1 lb_procs "$(nproc)"

    # Habilita o serviço
    [ -f /lib/systemd/system/zeek.service ] || cp /vagrant/resources/zeek/zeek.service /lib/systemd/system/zeek.service
    systemctl daemon-reload
    systemctl enable zeek
    systemctl start zeek
    systemctl status zeek
    systemctl is-active --quiet zeek || { log_stage "[X] Zeek failed to start."; return 1; }
    ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
    sleep 2

    # Verificação final
    if ! pgrep -f zeek >/dev/null; then
      log_stage "[X] Zeek failed to start. Exiting"
      WARNING+=("Zeek failed to start.")
      FIXES+=("Try start Zeek again manually.")
      return 1
    fi

    log_stage "[*] Zeek installed and working!"
    SUCCESS+=("Zeek is installed.")
  fi
}

## Install Velociraptor
install_velociraptor() {
  echo "[$(date +%H:%M:%S)]: Installing Velociraptor..."
  if [ ! -d "/opt/velociraptor" ]; then
    mkdir /opt/velociraptor || echo "Dir already exists"
  fi
  echo "[$(date +%H:%M:%S)]: Attempting to determine the URL for the latest release of Velociraptor"
  LATEST_VELOCIRAPTOR_LINUX_URL=$(curl -sL https://github.com/Velocidex/velociraptor/releases/ | grep linux-amd64 | grep href | head -1 | cut -d '"' -f 2 | sed 's#^#https://github.com#g')
  echo "[$(date +%H:%M:%S)]: The URL for the latest release was extracted as $LATEST_VELOCIRAPTOR_LINUX_URL"
  echo "[$(date +%H:%M:%S)]: Attempting to download..."
  wget -P /opt/velociraptor --progress=bar:force "$LATEST_VELOCIRAPTOR_LINUX_URL"
  if [ "$(file /opt/velociraptor/velociraptor*linux-amd64 | grep -c 'ELF 64-bit LSB executable')" -eq 1 ]; then
    echo "[$(date +%H:%M:%S)]: Velociraptor successfully downloaded!"
  else
    echo "[$(date +%H:%M:%S)]: Failed to download the latest version of Velociraptor. Please open a DetectionLab issue on Github."
    return
  fi

  cd /opt/velociraptor || exit 1
  mv velociraptor-*-linux-amd64 velociraptor
  chmod +x velociraptor
  cp /vagrant/resources/velociraptor/server.config.yaml /opt/velociraptor
  echo "[$(date +%H:%M:%S)]: Creating Velociraptor dpkg..."
  ./velociraptor --config /opt/velociraptor/server.config.yaml debian server
  echo "[$(date +%H:%M:%S)]: Cleanup velociraptor package building leftovers..."
  rm -rf /opt/velociraptor/logs
  echo "[$(date +%H:%M:%S)]: Installing the dpkg..."
  if dpkg -i velociraptor_*_server.deb >/dev/null; then
    echo "[$(date +%H:%M:%S)]: Installation complete!"
  else
    echo "[$(date +%H:%M:%S)]: Failed to install the dpkg"
    return
  fi
}

install_suricata() {
  echo -e "\n==========================================================================="
  log_stage " [*] Suricata Server Installation..."
  echo -e "==========================================================================="

  if command -v suricata >/dev/null 2>&1; then
    log_stage "[*] Suricata already installed."
    
    if systemctl is-active --quiet suricata; then
      log_stage "[*] Suricata service is running. Skipping installation."
      SUCCESS+=("Suricata is installed.")
    else
      log_stage "[X] Suricata service is installed but NOT running. Please check this service manually as soon as possible."
      WARNING+=("Suricata service is NOT running.")
      FIXES+=("Please check Suricata service manually as soon as possible.")
      return 1
    fi
  
  else
    # Run iwr -Uri testmyids.com -UserAgent "BlackSun" in Powershell to generate test alerts from Windows
    test_suricata_prerequisites
    log_stage "[+] Installing Suricata..."

    # Install suricata
    if "${APTFAST_CMD}" -y install suricata; then
      log_stage "[+] Suricata installed with success!"
      echo ""
      SUCCESS+=("Suricata was installed with success.")
    else
      log_stage "[X] Failed to install suricata. Aborting."
      ERROR+=("Suricata failed in the installation process.")
      return 1
    fi
    
    # Install suricata-update
    if ! command -v suricata-update >/dev/null; then
      log_stage "[+] suricata-update not found. Installing manually..."

      # Clona o repositório somente se não existir
      if [ ! -d "/opt/suricata-update" ]; then
        git clone https://github.com/OISF/suricata-update.git /opt/suricata-update || {
          log_stage "[X] Failed to clone suricata-update repository."
          ERROR+=("Failed to clone suricata-update repository.")
          return 1
        }
      fi

      cd /opt/suricata-update || {
        log_stage "[X] Failed to access /opt/suricata-update directory."
        ERROR+=("Failed to access /opt/suricata-update directory.")
        return 1
      }

      # Garante que o pyyaml esteja instalado
      if ! pip3 show pyyaml >/dev/null 2>&1; then
        pip3 install pyyaml || {
          log_stage "[X] Failed to install pyyaml."
          ERROR+=("Failed to install pyyaml")
          return 1
        }
      fi

      # Garante que o setuptools esteja disponível
      if ! python3 -c "import setuptools" 2>/dev/null; then
        log_stage "[!] setuptools not found. Installing fallback..."
        pip3 install setuptools || {
          log_stage "[X] Failed to install setuptools."
          ERROR+=("Failed to install setuptools")
          return 1
        }
      fi

      # Instala o suricata-update
      if python3 setup.py install; then
        log_stage "[+] suricata-update installed successfully."
        SUCCESS+=("suricata-update was installed with success")
      else
        log_stage "[X] Failed to install suricata-update via setup.py."
        ERROR+=("Failed to install suricata-update via setup.py")
        return 1
      fi
    else
      log_stage "[*] suricata-update already installed. Skipping installation."
      SUCCESS+=("suricata-update is installed")
    fi

    cp /vagrant/resources/suricata/suricata.yaml /etc/suricata/suricata.yaml
    crudini --set --format=sh /etc/default/suricata '' iface eth1
    
    # update suricata signature sources
    suricata-update update-sources
    
    # disable protocol decode as it is duplicative of Zeek
    echo re:protocol-command-decode >>/etc/suricata/disable.conf
    
    # enable et-open and attackdetection sources
    suricata-update enable-source et/open

    # Update suricata and restart
    suricata-update
    systemctl stop suricata 
    systemctl start suricata 
    systemctl status suricata 
    systemctl is-active --quiet suricata || { log_stage "[X] Suricata failed to start."; return 1; }
    sleep 3

    # Verify that Suricata is running
    if ! pgrep -f suricata >/dev/null; then
      log_stage "[X] Suricata attempted to start but is not running. Exiting"
      WARNING+=("Suricata attempted to start but is not running")
      return 1
    fi

    # Configure a logrotate policy for Suricata
    cat >/etc/logrotate.d/suricata <<EOF
/var/log/suricata/*.log /var/log/suricata/*.json
{
    hourly
    rotate 0
    missingok
    nocompress
    size=500M
    sharedscripts
    postrotate
            /bin/kill -HUP \`cat /var/run/suricata.pid 2>/dev/null\` 2>/dev/null || true
    endscript
}
EOF

  fi
}

## Guacamole Dependences
install_guacamole_dependencies() {
    echo "[+] Installing Guacamole build dependencies"
    echo "[*] Detected Ubuntu version: $UBUNTU_VERSION"

    # Common dependencies for all versions
    COMMON_PACKAGES=(
        libcairo2-dev
        libjpeg-turbo8-dev
        libpng-dev
        libtool-bin
        libossp-uuid-dev
        libssh2-1-dev
        libtelnet-dev
        libvncserver-dev
        libvorbis-dev
        libwebp-dev
        libpango1.0-dev
        libssl-dev
        libavcodec-dev
        libavutil-dev
        libswscale-dev
        python3-pip
        build-essential
        git
        unzip
    )

    # Version-specific dependencies
    if [[ "$UBUNTU_VERSION" == "18.04" ]]; then
        SPECIFIC_PACKAGES=(libfreerdp-dev)
    elif [[ "$UBUNTU_VERSION" == "20.04" ]]; then
        SPECIFIC_PACKAGES=(libfreerdp-dev)
    elif [[ "$UBUNTU_VERSION" == "22.04" ]]; then
        SPECIFIC_PACKAGES=(freerdp2-dev)
    elif [[ "$UBUNTU_VERSION" == "24.04" ]]; then
        SPECIFIC_PACKAGES=(freerdp2-dev)
    else
        echo "[!] Unsupported Ubuntu version detected. Trying defaults."
        SPECIFIC_PACKAGES=(freerdp2-dev)
    fi

    # Merge all packages
    ALL_PACKAGES=("${COMMON_PACKAGES[@]}" "${SPECIFIC_PACKAGES[@]}")

    # Install everything
    "${APTFAST_CMD}" install -y "${ALL_PACKAGES[@]}"
    
    echo "[+] Guacamole dependencies installed."
}

## Install Guacamole
install_guacamole() {
  echo "[$(date +%H:%M:%S)]: Setting up Guacamole..."
  cd /opt || exit 1
  echo "[$(date +%H:%M:%S)]: Downloading Guacamole..."
  wget --progress=bar:force "https://apache.org/dyn/closer.lua/guacamole/1.3.0/source/guacamole-server-1.3.0.tar.gz?action=download" -O guacamole-server-1.3.0.tar.gz
  tar -xf guacamole-server-1.3.0.tar.gz && cd guacamole-server-1.3.0 || echo "[-] Unable to find the Guacamole folder."
  echo "[$(date +%H:%M:%S)]: Configuring Guacamole and running 'make' and 'make install'..."
  ./configure --with-init-dir=/etc/init.d && make --quiet &>/dev/null && make --quiet install &>/dev/null || echo "[-] An error occurred while installing Guacamole."
  ldconfig
  cd /var/lib/tomcat9/webapps || echo "[-] Unable to find the tomcat9/webapps folder."
  wget --progress=bar:force "https://apache.org/dyn/closer.lua/guacamole/1.3.0/binary/guacamole-1.3.0.war?action=download" -O guacamole.war
  mkdir /etc/guacamole
  mkdir /etc/guacamole/shares
  sudo chmod 777 /etc/guacamole/shares
  mkdir /usr/share/tomcat9/.guacamole
  cp /vagrant/resources/guacamole/user-mapping.xml /etc/guacamole/
  cp /vagrant/resources/guacamole/guacamole.properties /etc/guacamole/
  cp /vagrant/resources/guacamole/guacd.service /lib/systemd/system
  sudo ln -s /etc/guacamole/guacamole.properties /usr/share/tomcat9/.guacamole/
  sudo ln -s /etc/guacamole/user-mapping.xml /usr/share/tomcat9/.guacamole/
  # Thank you Kifarunix: https://kifarunix.com/install-guacamole-on-debian-11/
  useradd -M -d /var/lib/guacd/ -r -s /sbin/nologin -c "Guacd User" guacd
  mkdir /var/lib/guacd
  chown -R guacd: /var/lib/guacd
  systemctl daemon-reload
  systemctl enable guacd
  systemctl enable tomcat9
  systemctl start guacd
  systemctl start tomcat9
  echo "[$(date +%H:%M:%S)]: Guacamole installation complete!"
}

configure_splunk_inputs() {
  echo -e "\n==========================================================================="
  log_stage " [+] Configuring Splunk Inputs Needs..."
  echo -e "==========================================================================="

  # Criação segura do diretório e arquivos para Splunk
  # Cria o diretório se ainda não existir
  if [ ! -d "/opt/splunk/etc/apps/search/local" ]; then
    mkdir -p /opt/splunk/etc/apps/search/local
    log_stage "[+] Created directory /opt/splunk/etc/apps/search/local"
  else
    log_stage "[*] Directory /opt/splunk/etc/apps/search/local already exists. Skipping."
  fi

  # Cria o arquivo inputs.conf se ainda não existir
  if [ ! -f "/opt/splunk/etc/apps/search/local/inputs.conf" ]; then
    touch /opt/splunk/etc/apps/search/local/inputs.conf
    log_stage "[+] Created file /opt/splunk/etc/apps/search/local/inputs.conf"
  else
    log_stage "[*] File /opt/splunk/etc/apps/search/local/inputs.conf already exists. Skipping."
  fi

  # Cria o arquivo props.conf se ainda não existir
  if [ ! -f "/opt/splunk/etc/apps/search/local/props.conf" ]; then
    touch /opt/splunk/etc/apps/search/local/props.conf
    log_stage "[+] Created file /opt/splunk/etc/apps/search/local/props.conf"
  else
    log_stage "[*] File /opt/splunk/etc/apps/search/local/props.conf already exists. Skipping."
  fi

  # Criação segura do diretório e arquivo para Splunk_TA_bro
  # Cria o diretório se ainda não existir
  if [ ! -d "/opt/splunk/etc/apps/Splunk_TA_bro/local" ]; then
    mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local
    echo "[+] Created directory /opt/splunk/etc/apps/Splunk_TA_bro/local"
  else
    echo "[*] Directory /opt/splunk/etc/apps/Splunk_TA_bro/local already exists. Skipping."
  fi

  # Cria o arquivo inputs.conf se ainda não existir
  if [ ! -f "/opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf" ]; then
    touch /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf
    echo "[+] Created file /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf"
  else
    echo "[*] File /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf already exists. Skipping."
  fi

  log_stage "Waiting for Splunk service to stabilize..."
  for i in {1..90}; do
    if /opt/splunk/bin/splunk status | grep -q "splunkd is running" && \
      curl -sk https://127.0.0.1:8089/services/server/info | grep -q "<title>server-info</title>"; then
      log_stage "[+] Deamon, apps/index Ok."
      break
    fi
    sleep 2
  done

  log_stage "[+] Configuring Splunk Inputs..."

  # --- Suricata ---
  if crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata index suricata \
  && crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata sourcetype suricata:json \
  && crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata whitelist 'eve.json' \
  && crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata disabled 0 \
  && crudini --set /opt/splunk/etc/apps/search/local/props.conf suricata:json TRUNCATE 0; then
    log_stage "[+] Suricata inputs configured successfully."
    SUCCESS+=("Suricata inputs configured successfully")
  else
    log_stage "[!] Failed to configure Suricata inputs for Splunk."
    WARNING+=("Failed to configure Suricata inputs for Splunk")
    FIXES+=("Check permissions on /opt/splunk/etc/apps/search/local/inputs.conf and re-run configuration for Suricata inputs")
  fi

  # --- Fleet ---
  if /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_result" -index osquery -sourcetype 'osquery:json' -auth "$SPLUNK_AUTH" --accept-license --answer-yes --no-prompt \
  && /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_status" -index osquery-status -sourcetype 'osquery:status' -auth "$SPLUNK_AUTH" --accept-license --answer-yes --no-prompt; then
    log_stage "[+] Fleet inputs configured successfully."
    SUCCESS+=("Fleet inputs configured successfully")
  else
    log_stage "[!] Failed to configure Fleet inputs for Splunk."
    WARNING+=("Failed to configure Zeek inputs for Splunk")
  fi

  # --- Zeek ---
  if crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager index zeek \
  && crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager sourcetype zeek:json \
  && crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager whitelist '.*\.log$' \
  && crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager blacklist '.*(communication|stderr)\.log$' \
  && crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager disabled 0; then
    log_stage "[+] Zeek inputs configured successfully."
    SUCCESS+=("Zeek inputs configured successfully")
  else
    log_stage "[!] Failed to configure Zeek inputs for Splunk."
    WARNING+=("Failed to configure Zeek inputs for Splunk")
    FIXES+=("Check permissions on /opt/splunk/etc/apps/search/local/inputs.conf and re-run configuration for Zeek inputs")
  fi

  # Ensure permissions are correct and restart splunk
  chown -R splunk:splunk /opt/splunk/etc/apps/Splunk_TA_bro
  /opt/splunk/bin/splunk restart
}

## View all ips to connect in the Splunk Web UI
check_splunk_web(){
  echo ""
  IPs=$(hostname -I | awk '{for(i=1;i<=NF;i++) print $i}')
  echo "The Splunk web interface is accessible at:"
  echo "  - https://localhost:8000"
  echo "  - https://127.0.0.1:8000"
  
  for ip in $IPs; do
    echo "  - https://$ip:8000"
  done
  
  echo "  - https://logger:8000"
  echo ""
}

## Health Check
final_healthcheck() {
    echo ""
    echo "==========================================================================="
    echo " [+] Running Final Healthcheck..."
    echo "==========================================================================="
    echo ""
    echo "✅  SUCCESS:"
    for msg in "${SUCCESS[@]}"; do
        echo "    - $msg"
    done

    if [ "${#WARNING[@]}" -ne 0 ]; then
        echo ""
        echo "⚠️  WARNINGS:"
        for msg in "${WARNING[@]}"; do
            echo "    - $msg"
        done
    fi

    if [ "${#ERROR[@]}" -ne 0 ]; then
        echo ""
        echo "❌  ERRORS:"
        for msg in "${ERROR[@]}"; do
            echo "    - $msg"
        done
    fi

    if [ "${#FIXES[@]}" -ne 0 ]; then
        echo ""
        echo "🛠️  MANUAL FIXES SUGGESTED:"
        for fix in "${FIXES[@]}"; do
            echo "    → $fix"
        done
    fi

    echo ""
    echo "==========================================================================="

    FAILED_MODULES=()
    # Se houver módulos que falharam, perguntar se deseja tentar reinstalar
    if [ "${#FAILED_MODULES[@]}" -gt 0 ]; then
        echo ""
        log_stage "Some modules failed: ${FAILED_MODULES[*]}"
        echo ""
        echo -n "Would you like to try reinstalling the failed modules? (yes/no) [Default: no]: "

        if [ -t 0 ]; then
            read -t 10 answer
            if [ $? -gt 0 ]; then
                answer="no"
                echo ""
                log_stage "[!] No answer provided within 10 seconds. Proceeding with 'no'."
            fi
        else
            answer="no"
            log_stage "[!] Non-interactive shell detected. Proceeding with 'no'."
        fi

        # Normalize input
        answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')

        if [[ "$answer" =~ ^(y|yes|sim|s)$ ]]; then
            echo ""
            log_stage "[*] Attempting to reinstall failed modules: ${FAILED_MODULES[*]}"

            for module in "${FAILED_MODULES[@]}"; do
                case "$module" in
                    "Guacamole")
                        install_guacamole
                        ;;
                    "Splunk")
                        install_splunk
                        ;;
                    "Suricata")
                        install_suricata
                        ;;
                    "Zeek")
                        install_zeek
                        ;;
                    "Fleet"|"Fleet (fleetctl)")
                        install_fleet_import_osquery_config
                        ;;
                    "Velociraptor")
                        install_velociraptor
                        ;;
                    *)
                        log_stage "[!] Unknown module '$module'. Skipping reinstall."
                        ;;
                esac
            done

            echo ""
            log_stage "[*] Re-running final healthcheck after retries..."
            final_healthcheck
        else
            echo ""
            log_stage "[*] Skipping reinstall. Ending script."
        fi
    fi
}

## Clean System
cleanup_system() {
    echo ""
    echo "==========================================================================="
    echo " [+] Performing final system cleanup..."
    echo "==========================================================================="

    # Limpeza de pacotes e cache
    log_stage "[*] Cleaning apt cache and removing unused packages..."
    apt-get clean
    apt-get autoremove --purge -y
    apt-get autoclean

    # Remover arquivos temporários gerados durante o processo
    log_stage "[-] Removing temporary downloaded files..."
    find /opt -type f \( -iname "*.tar.gz" -o -iname "*.deb" -o -iname "*.tar" \) -exec rm -f {} \;

    # Remover diretórios temporários de build se existirem
    log_stage "[-] Removing build directories..."
    rm -rf /opt/guacamole-server-*
    rm -rf /opt/fleet_*
    rm -rf /opt/fleetctl_*
    rm -rf /opt/suricata-update
    rm -rf /opt/velociraptor/*build*

    # Garantir remoção do lockfile, caso exista
    if [ -f "/tmp/provisioning.lock" ]; then
      log_stage "[-] Removing provisioning lockfile..."
      rm -f /tmp/provisioning.lock
    fi

    echo ""
    echo "==========================================="
    echo "[+] System cleanup completed successfully!"
    echo "==========================================="
}

## Method Main
# ==========================================
# Funções isoladas para execução de módulos específicos
# ==========================================

# Apenas Splunk (com pré-configuração necessária)
splunk_only() {
  update_system_and_install_dependencies
  modify_motd
  install_openvswitch
  fix_eth1_static_ip
  install_splunk
  configure_splunk_inputs
  check_splunk_web
  final_healthcheck
  cleanup_system
}

# Apenas Velociraptor
velociraptor_only() {
  update_system_and_install_dependencies
  modify_motd
  install_openvswitch
  fix_eth1_static_ip
  install_velociraptor
  final_healthcheck
  cleanup_system
}

# Apenas Guacamole
guacamole_only() {
  update_system_and_install_dependencies
  modify_motd
  install_openvswitch
  fix_eth1_static_ip
  install_guacamole
  final_healthcheck
  cleanup_system
}

# Apenas Suricata
suricata_only() {
  update_system_and_install_dependencies
  modify_motd
  install_openvswitch
  fix_eth1_static_ip
  install_suricata
  test_suricata_prerequisites
  final_healthcheck
  cleanup_system
}

# Apenas Zeek
zeek_only() {
  update_system_and_install_dependencies
  modify_motd
  install_openvswitch
  fix_eth1_static_ip
  install_zeek
  final_healthcheck
  cleanup_system
}

# Apenas Fleet
fleet_only() {
  update_system_and_install_dependencies
  modify_motd
  install_openvswitch
  fix_eth1_static_ip
  download_palantir_osquery_config
  install_fleet_import_osquery_config
  final_healthcheck
  cleanup_system
}

# Apenas DNS Fix
fix_dns_only() {
  fixing_DNS
}

main() {
  LOCKFILE="/tmp/provisioning.lock"
  if [ -f "$LOCKFILE" ]; then
    log_stage "[!] Provisionment is already working. Aborting..."
    exit 1
  fi
  touch "$LOCKFILE"
  trap "rm -f $LOCKFILE" EXIT

  echo ""
  echo "[*] Starting full provisioning..."

  MODULES=(
    "update_system_and_install_dependencies"
    "modify_motd"
    "install_openvswitch"
    "fix_eth1_static_ip"
    "install_suricata"
    "install_zeek"
    "download_palantir_osquery_config"
    "install_fleet_import_osquery_config"
    "install_splunk"
    "install_velociraptor"
    "install_guacamole"
    "configure_splunk_inputs"
    "check_splunk_web"
  )

  for module in "${MODULES[@]}"; do
    if $module; then
      echo "✅ $module completed successfully."
    else
      echo "❌ $module failed. Continuing with next steps..."
      FAILED_MODULES+=("$module")
    fi
  done

  echo ""
  final_healthcheck
  cleanup_system

  END_TIME=$(date +%s)
  ELAPSED_TIME=$((END_TIME - START_TIME))
  echo ""
  echo "==========================================================================="
  echo " [+] Provisioning completed in ${ELAPSED_TIME} seconds!"
  echo "==========================================================================="
}

# Lista de modos permitidos
ALLOWED_MODES=("main" "splunk_only" "velociraptor_only" "guacamole_only" "suricata_only" "zeek_only" "fleet_only" "fix_dns_only" "cleanup_system")

# Execução segura
if [[ -n "${1:-}" ]]; then
  MODE="${1,,}"
  if [[ " ${ALLOWED_MODES[*]} " =~ " $MODE " ]]; then
    $MODE
  else
    echo "[!] Invalid mode: '$1'"
    echo "Available modes are: ${ALLOWED_MODES[*]}"
    exit 1
  fi
else
  main
fi

exit $?
