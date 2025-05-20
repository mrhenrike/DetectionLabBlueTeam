#! /usr/bin/env bash
# shellcheck disable=SC1091,SC2129

# This is the script that is used to provision the logger host

SPLUNK_AUTH='admin:changeme'
SPLUNK_PATH="/opt/splunk"
ZEEK_PATH="/opt/zeek"
exec > >(tee -a /var/log/logger_provision.log) 2>&1

## Log stage
log_stage() {
  echo "[$(date +%H:%M:%S)]: $1"
}

log_stage "Starting Looger Boostrap!"

# Override existing DNS Settings using netplan, but don't do it for Terraform AWS builds
chmod 600 /etc/netplan/*.yaml 2>/dev/null
if ! curl -s 169.254.169.254 --connect-timeout 2 >/dev/null; then
  echo -e "    eth1:\n      dhcp4: true\n      nameservers:\n        addresses: [8.8.8.8,8.8.4.4]" >>/etc/netplan/01-netcfg.yaml
  netplan apply
fi

# Kill systemd-resolvd, just use plain ol' /etc/resolv.conf
systemctl disable systemd-resolved
systemctl stop systemd-resolved
rm /etc/resolv.conf
echo 'nameserver 8.8.8.8' >> /etc/resolv.conf
echo 'nameserver 8.8.4.4' >> /etc/resolv.conf
echo 'nameserver 192.168.56.102' >> /etc/resolv.conf

# Source variables from logger_variables.sh
# shellcheck disable=SC1091
source /vagrant/logger_variables.sh 2>/dev/null ||
  source /home/vagrant/logger_variables.sh 2>/dev/null ||
  echo "Unable to locate logger_variables.sh"

if [ -z "$MAXMIND_LICENSE" ]; then
  echo "Note: You have not entered a MaxMind API key in logger_variables.sh, so the ASNgen Splunk app may not work correctly."
  echo "However, it is optional and everything else should function correctly."
fi

export DEBIAN_FRONTEND=noninteractive
echo "apt-fast apt-fast/maxdownloads string 10" | debconf-set-selections
echo "apt-fast apt-fast/dlflag boolean true" | debconf-set-selections

apt_install_prerequisites() {
  log_stage "Adding apt repositories..."
  
  if ! grep -q "apt-fast" /etc/apt/sources.list.d/*; then
    add-apt-repository -y -n ppa:apt-fast/stable
  fi
  if ! grep -q "rmescandon" /etc/apt/sources.list.d/*; then
    add-apt-repository -y -n ppa:rmescandon/yq 
  fi
  if ! grep -q "oisf" /etc/apt/sources.list.d/*; then
    add-apt-repository -y -n ppa:oisf/suricata-stable 
  fi

   
  # Install prerequisites and useful tools
  log_stage "Running apt-get clean..."
  apt-get clean
  log_stage "Running apt-get update..."
  apt-get -qq update
  log_stage "Installing apt-fast..."
  apt-get -qq install -y apt-fast
  log_stage "Using apt-fast to install packages..."
  apt-fast install --no-install-recommends -y jq whois build-essential git unzip htop yq mysql-server redis-server python3-pip libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin libossp-uuid-dev libavcodec-dev libavutil-dev libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libvncserver-dev libtelnet-dev libssl-dev libvorbis-dev libwebp-dev tomcat9 tomcat9-admin tomcat9-user tomcat9-common net-tools
}

modify_motd() {
  log_stage "Updating the MOTD..."
  # Force color terminal
  sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/g' /root/.bashrc
  sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/g' /home/vagrant/.bashrc
  # Remove some stock Ubuntu MOTD content
  chmod -x /etc/update-motd.d/10-help-text
  # Copy the DetectionLab MOTD
  [ -f /etc/update-motd.d/20-detectionlab ] || cp /vagrant/resources/logger/20-detectionlab /etc/update-motd.d/
  chmod +x /etc/update-motd.d/20-detectionlab
}

test_prerequisites() {
  dpkg -s crudini >/dev/null 2>&1 || apt-fast install -y crudini
  for package in jq whois build-essential git unzip yq mysql-server redis-server python3-pip; do
    log_stage "[TEST] Validating that $package is correctly installed..."
    
    # Loop through each package using dpkg
    if ! dpkg -S $package >/dev/null; then
      
      # If which returns a non-zero return code, try to re-install the package
      log_stage "[-] $package was not found. Attempting to reinstall."
      apt-get -qq update && apt-get install -y $package
      if ! which $package >/dev/null; then
        # If the reinstall fails, give up
        log_stage "[X] Unable to install $package even after a retry. Exiting."
        exit 1
      fi
    else
      log_stage "[+] $package was successfully installed!"
    fi
  done
}

fix_eth1_static_ip() {
  USING_KVM=$(sudo lsmod | grep kvm)
  if [ -n "$USING_KVM" ]; then
    log_stage "[*] Using KVM, no need to fix DHCP for eth1 iface"
    return 0
  fi
  if [ -f /sys/class/net/eth2/address ]; then
    if [ "$(cat /sys/class/net/eth2/address)" == "00:50:56:a3:b1:c4" ]; then
      log_stage "[*] Using ESXi, no need to change anything"
      return 0
    fi
  fi
  # TODO: try to set correctly directly through vagrant net config
  netplan set --origin-hint 90-disable-eth1-dhcp ethernets.eth1.dhcp4=false
  netplan apply

  # Fix eth1 if the IP isn't set correctly
  ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
  if [ "$ETH1_IP" != "192.168.56.105" ]; then
    log_stage "Incorrect IP Address settings detected. Attempting to fix."
    ip link set dev eth1 down
    ip addr flush dev eth1
    ip link set dev eth1 up
    counter=0
    while :; do
      ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
      if [ "$ETH1_IP" == "192.168.56.105" ]; then
        log_stage "The static IP has been fixed and set to 192.168.56.105"
        break
      else
        if [ $counter -le 20 ]; then
          let counter=counter+1
          log_stage "Waiting for IP $counter/20 seconds"
          sleep 1
          continue
        else
          log_stage "Failed to fix the broken static IP for eth1. Exiting because this will cause problems with other VMs."
          log_stage "eth1's current IP address is $ETH1_IP"
          exit 1
        fi
      fi
    done
  fi

  # Make sure we do have a DNS resolution
  while true; do
    if [ "$(dig +short @8.8.8.8 github.com)" ]; then break; fi
    sleep 1
  done
}

install_splunk() {
  # Check if Splunk is already installed
  if [ -f "/opt/splunk/bin/splunk" ]; then
    log_stage "Splunk is already installed"
  else
    log_stage "Installing Splunk..."
    # Get download.splunk.com into the DNS cache. Sometimes resolution randomly fails during wget below
    dig @8.8.8.8 download.splunk.com >/dev/null
    dig @8.8.8.8 splunk.com >/dev/null
    dig @8.8.8.8 www.splunk.com >/dev/null

    # Prime DNS cache to avoid flaky wget failures
    for domain in download.splunk.com splunk.com www.splunk.com; do
      dig @$DNS_SERVER "$domain" >/dev/null 2>&1 || true
    done

    # Try to resolve latest Splunk version
    log_stage "Attempting to autoresolve the latest version of Splunk..."
    LATEST_SPLUNK=$(curl -fsSL https://www.splunk.com/en_us/download/splunk-enterprise.html | \
      grep -oP 'https://download\.splunk\.com[^\"]+\.deb' | head -n1)

    if [[ "$LATEST_SPLUNK" =~ \.deb$ ]]; then
      log_stage "Resolved latest Splunk URL: $LATEST_SPLUNK"
      SPLUNK_FILENAME="/opt/$(basename "$LATEST_SPLUNK")"
      wget --progress=bar:force -O "$SPLUNK_FILENAME" "$LATEST_SPLUNK"
    else
      log_stage "Auto-resolve failed. Falling back to hardcoded URL..."
      SPLUNK_FILENAME="/opt/splunk-9.4.1-e3bdab203ac8-linux-amd64.deb"
      wget --progress=bar:force -O "$SPLUNK_FILENAME" "https://download.splunk.com/products/splunk/releases/9.4.1/linux/splunk-9.4.1-e3bdab203ac8-linux-amd64.deb"
    fi
    
    # Validate and install
    if [[ "$SPLUNK_FILENAME" =~ splunk-[0-9]+\.[0-9]+\.[0-9]+.*\.deb$ ]]; then
      log_stage "[+] Splunk file valid detected."
    else
      log_stage "[X] Invalid file for Splunk. Aborting."
      exit 1
    fi
    if [ -f "$SPLUNK_FILENAME" ]; then
      log_stage "Installing $SPLUNK_FILENAME..."
      if ! dpkg -i "$SPLUNK_FILENAME" >/dev/null; then
        log_stage "Splunk installation failed. Exiting."
        exit 1
      fi
    else
      log_stage "Splunk .deb file not found. Exiting."
      exit 1
    fi

    ln -sf /opt/splunk/bin/splunk /usr/local/bin/splunk

    /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
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
      mkdir /opt/splunk/etc/apps/TA-asngen/local
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
    mkdir /opt/splunk/etc/apps/Splunk_TA_bro/local && cp /vagrant/resources/splunk_server/zeek_ta_props.conf /opt/splunk/etc/apps/Splunk_TA_bro/local/props.conf

    # Add custom Macro definitions for ThreatHunting App
    [ -f /opt/splunk/etc/apps/ThreatHunting/default/macros.conf ] || cp /vagrant/resources/splunk_server/macros.conf /opt/splunk/etc/apps/ThreatHunting/default/macros.conf
    
    # Fix some misc stuff
    # shellcheck disable=SC2016
    sed -i 's/index=windows/`windows`/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
    
    # shellcheck disable=SC2016
    sed -i 's/$host$)/$host$*)/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
    
    # This is probably horrible and may break some stuff, but I'm hoping it fixes more than it breaks
    find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/host_fqdn/ComputerName/g' {} \;
    find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/event_id/EventCode/g' {} \;

    # Fix Windows TA macros
    mkdir /opt/splunk/etc/apps/Splunk_TA_windows/local
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
    log_stage "Disabling the Splunk tour prompt..."
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

download_palantir_osquery_config() {
  if [ -d "/opt/osquery-configuration" ]; then
    log_stage "osquery configs have already been downloaded"
  else
    log_stage "Downloading Palantir osquery configs..."
    git clone https://github.com/palantir/osquery-configuration.git /opt/osquery-configuration
  fi
}


install_fleet_import_osquery_config() {
  if [ -d "/opt/fleet" ]; then
    log_stage "Fleet is already installed"
  else
    cd /opt && mkdir /opt/fleet || exit 1

    log_stage "Installing Fleet..."
    if ! grep 'fleet' /etc/hosts; then
      echo -e "\n127.0.0.1       fleet" >>/etc/hosts
    fi
    if ! grep 'logger' /etc/hosts; then
      echo -e "\n127.0.0.1       logger" >>/etc/hosts
    fi

    # Set MySQL username and password, create fleet database
    mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'fleet';"
    mysql -uroot -pfleet -e "create database fleet;"

    # Always download the latest release of Fleet and Fleetctl
    curl -s https://api.github.com/repos/fleetdm/fleet/releases/latest | jq '.assets[] | select(.name|match("linux.tar.gz$")) | .browser_download_url' | sed 's/"//g' | grep fleetctl  | wget --progress=bar:force -i -
    curl -s https://api.github.com/repos/fleetdm/fleet/releases/latest | jq '.assets[] | select(.name|match("linux.tar.gz$")) | .browser_download_url' | sed 's/"//g' | grep fleet | grep -v fleetctl | wget --progress=bar:force -i -
    tar -xvf fleet_*.tar.gz
    tar -xvf fleetctl_*.tar.gz
    cp fleetctl_*/fleetctl /usr/local/bin/fleetctl && chmod +x /usr/local/bin/fleetctl
    cp fleet_*/fleet /usr/local/bin/fleet && chmod +x /usr/local/bin/fleet

    if ! command -v fleetctl &>/dev/null; then
      log_stage "[X] fleetctl não foi instalado corretamente. Abortando."
      exit 1
    fi

    # Prepare the DB
    fleet prepare db --mysql_address=127.0.0.1:3306 --mysql_database=fleet --mysql_username=root --mysql_password=fleet

    # Copy over the certs and service file
    cp /vagrant/resources/fleet/server.* /opt/fleet/
    [ -f /etc/systemd/system/fleet.service ] || cp /vagrant/resources/fleet/fleet.service /etc/systemd/system/fleet.service

    # Create directory for logs
    mkdir /var/log/fleet

    # Install the service file
    /bin/systemctl enable fleet.service
    /bin/systemctl start fleet.service
    systemctl is-active --quiet fleet || { log_stage "[X] Fleet failed to start."; exit 1; }

    # Start Fleet
    log_stage "Waiting for fleet service to start..."
    while true; do
      result=$(curl --silent -k https://127.0.0.1:8412)
      if echo "$result" | grep -q setup; then break; fi
      sleep 1
    done

    fleetctl config set --address https://192.168.56.105:8412
    fleetctl config set --tls-skip-verify true
    if ! fleetctl config get | grep -q 'https://'; then
      fleetctl setup --email admin@detectionlab.network --name admin --password 'Fl33tpassword!' --org-name DetectionLab
    fi
    fleetctl login --email admin@detectionlab.network --password 'Fl33tpassword!'

    # Set the enrollment secret to match what we deploy to Windows hosts
    if mysql -uroot --password=fleet -e 'use fleet; INSERT INTO enroll_secrets(created_at, secret, team_id) VALUES ("2022-05-30 21:20:23", "enrollmentsecretenrollmentsecret", NULL);'; then
      log_stage "Updated enrollment secret"
    else
      log_stage "Error adding the custom enrollment secret. This is going to cause problems with agent enrollment."
    fi

    # Change the query invervals to reflect a lab environment
    # Every hour -> Every 3 minutes
    # Every 24 hours -> Every 15 minutes
    if ! fleetctl get queries | grep -q "Scheduled"; then
      fleetctl apply -f osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    fi

    sed -i 's/interval: 3600/interval: 300/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 3600/interval: 300/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    sed -i 's/interval: 28800/interval: 1800/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 28800/interval: 1800/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    sed -i 's/interval: 0/interval: 1800/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 0/interval: 1800/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml

    # Don't log osquery INFO messages
    # Fix snapshot event formatting
    fleetctl get config >/tmp/config.yaml
    /usr/bin/yq eval -i '.spec.agent_options.config.options.enroll_secret = "enrollmentsecretenrollmentsecret"' /tmp/config.yaml
    /usr/bin/yq eval -i '.spec.agent_options.config.options.logger_snapshot_event_type = true' /tmp/config.yaml
    fleetctl apply -f /tmp/config.yaml

    # Use fleetctl to import YAML files
    fleetctl apply -f osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    fleetctl apply -f osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    for pack in osquery-configuration/Fleet/Endpoints/packs/*.yaml; do
      fleetctl apply -f "$pack"
    done

    # Add Splunk monitors for Fleet
    # Files must exist before splunk will add a monitor
    touch /var/log/fleet/osquery_result
    touch /var/log/fleet/osquery_status
  fi
}

install_zeek() {
  if [ -f /opt/zeek/bin/zeek ]; then
    log_stage "Zeek already installed, skipping..."
    return 0
  fi

  log_stage "Installing Zeek..."

  NODECFG=/opt/zeek/etc/node.cfg

  # Detectar versão do Ubuntu
  UBUNTU_VERSION=$(lsb_release -rs)

  # Definir a variável de repositório do Zeek baseado na versão detectada
  case "$UBUNTU_VERSION" in
    18.04)
      ZEEK_REPO_VERSION="xUbuntu_18.04"
      ;;
    20.04)
      ZEEK_REPO_VERSION="xUbuntu_20.04"
      ;;
    22.04)
      ZEEK_REPO_VERSION="xUbuntu_22.04"
      ;;
    24.04)
      ZEEK_REPO_VERSION="xUbuntu_24.04"
      ;;
    *)
      echo "[$(date +%H:%M:%S)]: [X] Ubuntu version $UBUNTU_VERSION not supported for Zeek installation."
      exit 1
      ;;
  esac

  # Agora usa a variável para configurar o repositório
  log_stage "Adding Zeek repository..."
  log_stage "Setting Zeek repository for $ZEEK_REPO_VERSION"
  echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPO_VERSION}/ /" > /etc/apt/sources.list.d/zeek.list

  # E baixa a chave GPG correta
  log_stage "Adding Zeek GPG key..."
  curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPO_VERSION}/Release.key" | gpg --dearmor -o /usr/share/keyrings/zeek-archive-keyring.gpg

  apt-get update -y
  apt-get install -y zeek-lts crudini

  if ! command -v zeek-config &>/dev/null; then
    log_stage "[X] zeek-config not found. Installation failed."
    exit 1
  fi

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
  systemctl daemon-reexec
  systemctl enable zeek
  systemctl start zeek
  systemctl is-active --quiet zeek || { log_stage "[X] Zeek failed to start."; exit 1; }
  ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
  sleep 2

  # Verificação final
  if ! pgrep -f zeek >/dev/null; then
    log_stage "[X] Zeek failed to start. Exiting"
    exit 1
  fi

  log_stage "Zeek installed and working!"
}


install_velociraptor() {
  log_stage "Installing Velociraptor..."
  if [ ! -d "/opt/velociraptor" ]; then
    mkdir /opt/velociraptor || echo "Dir already exists"
  fi
  log_stage "Attempting to determine the URL for the latest release of Velociraptor"
  LATEST_VELOCIRAPTOR_LINUX_URL=$(curl -sL https://github.com/Velocidex/velociraptor/releases/ | grep linux-amd64 | grep href | head -1 | cut -d '"' -f 2 | sed 's#^#https://github.com#g')
 
  if [ -z "$LATEST_VELOCIRAPTOR_LINUX_URL" ]; then
    log_stage "[X] Failed to resolve Velociraptor release URL. Aborting."
    return
  fi

  log_stage "The URL for the latest release was extracted as $LATEST_VELOCIRAPTOR_LINUX_URL"
  log_stage "Attempting to download..."
  wget -P /opt/velociraptor --progress=bar:force "$LATEST_VELOCIRAPTOR_LINUX_URL"
  if [ "$(file /opt/velociraptor/velociraptor*linux-amd64 | grep -c 'ELF 64-bit LSB executable')" -eq 1 ]; then
    log_stage "Velociraptor successfully downloaded!"
  else
    log_stage "Failed to download the latest version of Velociraptor. Please open a DetectionLab issue on Github."
    return
  fi

  cd /opt/velociraptor || exit 1
  mv velociraptor-*-linux-amd64 velociraptor
  chmod +x velociraptor
  cp /vagrant/resources/velociraptor/server.config.yaml /opt/velociraptor

  log_stage "Creating Velociraptor dpkg..."
  ./velociraptor --config /opt/velociraptor/server.config.yaml debian server

  log_stage "Cleanup velociraptor package building leftovers..."
  rm -rf /opt/velociraptor/logs

  log_stage "Installing the dpkg..."
  DEB_FILE=$(find . -name "velociraptor*.deb" | head -n1)

  if dpkg -i "$DEB_FILE" >/dev/null; then
    log_stage "Installation complete!"
  else
    log_stage "Failed to install the dpkg"
    return
  fi

}

install_suricata() {
  # Run iwr -Uri testmyids.com -UserAgent "BlackSun" in Powershell to generate test alerts from Windows
  log_stage "Installing Suricata..."

  # Install suricata
  apt-get -qq -y install suricata crudini
  test_suricata_prerequisites
  
  # Install suricata-update
  cd /opt || exit 1
  
  #git clone https://github.com/OISF/suricata-update.git
  [ -d "/opt/suricata-update" ] || git clone https://github.com/OISF/suricata-update.git
  cd /opt/suricata-update || exit 1
  pip3 install pyyaml
  python3 setup.py install

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
  systemctl is-active --quiet suricata || { log_stage "[X] Suricata failed to start."; exit 1; }
  sleep 3

  # Verify that Suricata is running
  if ! pgrep -f suricata >/dev/null; then
    log_stage "Suricata attempted to start but is not running. Exiting"
    exit 1
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

}

test_suricata_prerequisites() {
  for package in suricata crudini; do
    log_stage "[TEST] Validating that $package is correctly installed..."
    
    # Loop through each package using dpkg
    if ! dpkg -S $package >/dev/null; then
      
      # If which returns a non-zero return code, try to re-install the package
      log_stage "[-] $package was not found. Attempting to reinstall."
      apt-get clean && apt-get -qq update && apt-get install -y $package
      if ! which $package >/dev/null; then
        
        # If the reinstall fails, give up
        log_stage "[X] Unable to install $package even after a retry. Exiting."
        exit 1
      fi
    else
      log_stage "[+] $package was successfully installed!"
    fi
  done
}

install_guacamole() {
  log_stage "Setting up Guacamole..."
  cd /opt || exit 1
  
  log_stage "Downloading Guacamole..."
  wget --progress=bar:force "https://apache.org/dyn/closer.lua/guacamole/1.3.0/source/guacamole-server-1.3.0.tar.gz?action=download" -O guacamole-server-1.3.0.tar.gz
  tar -xf guacamole-server-1.3.0.tar.gz && cd guacamole-server-1.3.0 || echo "[-] Unable to find the Guacamole folder."
  
  log_stage "Configuring Guacamole and running 'make' and 'make install'..."
  ./configure --with-init-dir=/etc/init.d && make --quiet &>/dev/null && make --quiet install &>/dev/null || echo "[-] An error occurred while installing Guacamole."
  ldconfig
  cd /var/lib/tomcat9/webapps || echo "[-] Unable to find the tomcat9/webapps folder."
  wget --progress=bar:force "https://apache.org/dyn/closer.lua/guacamole/1.3.0/binary/guacamole-1.3.0.war?action=download" -O guacamole.war
  mkdir /etc/guacamole
  mkdir /etc/guacamole/shares
  sudo chmod 777 /etc/guacamole/shares
  mkdir /usr/share/tomcat9/.guacamole
  [ -f /etc/guacamole/user-mapping.xml ] || cp /vagrant/resources/guacamole/user-mapping.xml /etc/guacamole/
  [ -f /etc/guacamole/guacamole.properties ] || cp /vagrant/resources/guacamole/guacamole.properties /etc/guacamole/
  [ -f /lib/systemd/system/guacd.service ] || cp /vagrant/resources/guacamole/guacd.service /lib/systemd/system
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
  systemctl is-active --quiet guacd || { log_stage "[X] Guacamole failed to start."; exit 1; }

  systemctl start tomcat9
  systemctl is-active --quiet tomcat9 || { log_stage "[X] Tomcat failed to start."; exit 1; }

  log_stage "Guacamole installation complete!"
}

configure_splunk_inputs() {
  log_stage "Configuring Splunk Inputs..."
  
  # Suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata index suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata sourcetype suricata:json
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata whitelist 'eve.json'
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata disabled 0
  crudini --set /opt/splunk/etc/apps/search/local/props.conf suricata:json TRUNCATE 0

  # Fleet
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_result" -index osquery -sourcetype 'osquery:json' -auth "$SPLUNK_AUTH" --accept-license --answer-yes --no-prompt
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_status" -index osquery-status -sourcetype 'osquery:status' -auth "$SPLUNK_AUTH" --accept-license --answer-yes --no-prompt

  # Zeek
  mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local && touch /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager index zeek
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager sourcetype zeek:json
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager whitelist '.*\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager blacklist '.*(communication|stderr)\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager disabled 0

  # Ensure permissions are correct and restart splunk
  chown -R splunk:splunk /opt/splunk/etc/apps/Splunk_TA_bro
  /opt/splunk/bin/splunk restart
}

while ! dig +short github.com > /dev/null; do
  log_stage "Waiting for DNS to resolve..."
  sleep 1
done


main() {
  LOCKFILE="/tmp/provisioning.lock"
  if [ -f "$LOCKFILE" ]; then
    log_stage "[!] Provisionment is already working. Aborting..."
    exit 1
  fi
  touch "$LOCKFILE"
  trap "rm -f $LOCKFILE" EXIT

  apt_install_prerequisites
  modify_motd
  test_prerequisites
  fix_eth1_static_ip
  install_splunk
  download_palantir_osquery_config
  install_fleet_import_osquery_config
  install_velociraptor
  install_suricata
  install_zeek
  install_guacamole
  configure_splunk_inputs
}

splunk_only() {
  install_splunk
  configure_splunk_inputs
}

velociraptor_only() {
  install_velociraptor
}

# Allow custom modes via CLI args
if [ -n "$1" ]; then
  eval "$1"
else
  main
fi
exit 0
