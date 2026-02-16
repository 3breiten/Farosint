#!/bin/bash
###############################################################################
# FAROSINT - Instalador Completo para Debian 12
# Instala TODO: aplicación, herramientas, desktop, branding, servicios
#
# Uso: sudo bash install.sh
#
# Requisitos: Debian 12 recién instalado (mínimo o netinstall)
# Resultado: Sistema Farosint completo listo para usar
###############################################################################

set -e

# ============================================================================
# VARIABLES
# ============================================================================
FAROSINT_USER="farosint"
FAROSINT_HOME="/home/${FAROSINT_USER}"
FAROSINT_DIR="${FAROSINT_HOME}/FAROSINT"
SYSTEM_DIR="${FAROSINT_DIR}/system"
GO_VERSION="1.22.5"
AMASS_VERSION="v5.0.0"
HOSTNAME_NEW="farosint-workstation"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ============================================================================
# FUNCIONES
# ============================================================================

log_step() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================${NC}\n"
}

log_ok() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}  ⚠ $1${NC}"
}

log_error() {
    echo -e "${RED}  ✗ $1${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script debe ejecutarse como root (sudo bash install.sh)"
        exit 1
    fi
}

check_debian() {
    if [ ! -f /etc/debian_version ]; then
        log_error "Este script requiere Debian"
        exit 1
    fi
    local version
    version=$(cat /etc/debian_version | cut -d. -f1)
    if [ "$version" != "12" ]; then
        log_warn "Diseñado para Debian 12, detectado: $(cat /etc/debian_version)"
    fi
}

# ============================================================================
# PASO 1: VERIFICACIONES INICIALES
# ============================================================================

check_root
check_debian

log_step "FAROSINT - Instalador Completo para Debian 12"
echo "Este script instalará:"
echo "  - Entorno gráfico (Openbox + LightDM + tint2)"
echo "  - Herramientas OSINT (Nmap, Nuclei, Amass, Subfinder, etc.)"
echo "  - Aplicación FAROSINT (dashboard web + CLI)"
echo "  - Servicios (SSH, xRDP)"
echo "  - Branding completo (wallpaper, logo, menú)"
echo ""
echo "Usuario: ${FAROSINT_USER} (debe existir — crearlo al instalar Debian)"
echo ""
read -p "¿Continuar? (s/N): " confirm
if [[ ! "$confirm" =~ ^[sS]$ ]]; then
    echo "Instalación cancelada."
    exit 0
fi

# ============================================================================
# PASO 2: CONFIGURACIÓN INICIAL DEL SISTEMA
# ============================================================================

log_step "Paso 1/12: Configuración inicial del sistema"

# Hostname
hostnamectl set-hostname "${HOSTNAME_NEW}"
echo "${HOSTNAME_NEW}" > /etc/hostname
sed -i "s/127.0.1.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts
log_ok "Hostname: ${HOSTNAME_NEW}"

# Verificar que el usuario existe (debe crearse durante la instalación de Debian)
if ! id "${FAROSINT_USER}" &>/dev/null; then
    log_error "El usuario '${FAROSINT_USER}' no existe."
    log_error "Debés crear el usuario '${FAROSINT_USER}' durante la instalación de Debian."
    exit 1
fi

# Asegurar que esté en los grupos necesarios
usermod -aG sudo,ssl-cert "${FAROSINT_USER}"
log_ok "Usuario ${FAROSINT_USER} verificado, grupos actualizados (sudo, ssl-cert)"

# ============================================================================
# PASO 3: PAQUETES DEL SISTEMA
# ============================================================================

log_step "Paso 2/12: Instalando paquetes del sistema"

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq

# Entorno gráfico
apt-get install -y -qq \
    xorg openbox obconf lightdm lightdm-gtk-greeter \
    tint2 feh jgmenu picom \
    x11-apps x11-utils x11-xserver-utils \
    xterm pcmanfm \
    firefox-esr \
    fonts-noto-core fonts-noto-mono \
    > /dev/null 2>&1
log_ok "Entorno gráfico (Openbox + LightDM + tint2 + jgmenu)"

# Herramientas de seguridad (apt)
apt-get install -y -qq \
    nmap \
    dnsrecon \
    whatweb \
    gobuster \
    snmp snmpd \
    whois \
    net-tools \
    bind9-dnsutils \
    dirb \
    perl libnet-ssleay-perl \
    > /dev/null 2>&1
log_ok "Herramientas de seguridad (nmap, dnsrecon, whatweb, gobuster, snmp)"

# Desarrollo y build
apt-get install -y -qq \
    build-essential gcc make \
    python3 python3-dev python3-venv python3-pip \
    libxml2-dev libxslt1-dev libffi-dev libssl-dev \
    git curl wget unzip \
    sqlite3 \
    > /dev/null 2>&1
log_ok "Herramientas de desarrollo (python3, gcc, git, etc.)"

# Servicios
apt-get install -y -qq \
    openssh-server \
    xrdp xorgxrdp \
    > /dev/null 2>&1
log_ok "Servicios (SSH, xRDP)"

# Habilitar servicios
systemctl enable ssh
systemctl enable xrdp
systemctl enable lightdm
log_ok "Servicios habilitados (ssh, xrdp, lightdm)"

# ============================================================================
# PASO 4: INSTALAR GO
# ============================================================================

log_step "Paso 3/12: Instalando Go ${GO_VERSION}"

if [ ! -f /usr/local/go/bin/go ]; then
    cd /tmp
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
    log_ok "Go ${GO_VERSION} instalado en /usr/local/go"
else
    log_ok "Go ya instalado"
fi

# Configurar PATH para Go (para este script)
export GOROOT=/usr/local/go
export GOPATH="${FAROSINT_HOME}/go"
export PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Crear directorio Go para el usuario
mkdir -p "${GOPATH}/bin"
chown -R "${FAROSINT_USER}:${FAROSINT_USER}" "${GOPATH}"

# ============================================================================
# PASO 5: INSTALAR HERRAMIENTAS GO (como usuario farosint)
# ============================================================================

log_step "Paso 4/12: Instalando herramientas Go (Subfinder, Nuclei, Httpx)"

su - "${FAROSINT_USER}" -c "
    export GOROOT=/usr/local/go
    export GOPATH=\$HOME/go
    export PATH=\$PATH:\$GOROOT/bin:\$GOPATH/bin

    echo '  Instalando subfinder...'
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null

    echo '  Instalando nuclei...'
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null

    echo '  Instalando httpx...'
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
"
log_ok "Subfinder, Nuclei, Httpx instalados"

# Actualizar templates de Nuclei
su - "${FAROSINT_USER}" -c "
    export PATH=\$PATH:\$HOME/go/bin
    nuclei -update-templates 2>/dev/null || true
"
log_ok "Nuclei templates actualizados"

# ============================================================================
# PASO 6: INSTALAR AMASS (binario precompilado)
# ============================================================================

log_step "Paso 5/12: Instalando Amass ${AMASS_VERSION}"

if [ ! -f /usr/local/bin/amass ]; then
    cd /tmp
    AMASS_URL="https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_Linux_amd64.zip"
    wget -q "${AMASS_URL}" -O amass.zip || {
        log_warn "No se pudo descargar Amass ${AMASS_VERSION}, intentando latest..."
        wget -q "https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip" -O amass.zip
    }
    unzip -o -q amass.zip -d amass_tmp
    # El binario puede estar en la raíz o en un subdirectorio
    find amass_tmp -name "amass" -type f -executable -exec cp {} /usr/local/bin/amass \;
    chmod +x /usr/local/bin/amass
    rm -rf amass.zip amass_tmp
    log_ok "Amass instalado en /usr/local/bin/amass"
else
    log_ok "Amass ya instalado"
fi

# ============================================================================
# PASO 7: INSTALAR HERRAMIENTAS MANUALES (nikto, enum4linux-ng, theHarvester)
# ============================================================================

log_step "Paso 6/12: Instalando herramientas manuales"

TOOLS_DIR="${FAROSINT_HOME}/tools"
mkdir -p "${TOOLS_DIR}"

# Nikto
if [ ! -d "${TOOLS_DIR}/nikto" ]; then
    git clone -q https://github.com/sullo/nikto.git "${TOOLS_DIR}/nikto"
    log_ok "Nikto instalado en ${TOOLS_DIR}/nikto"
else
    log_ok "Nikto ya instalado"
fi

# enum4linux-ng
if [ ! -d "${TOOLS_DIR}/enum4linux-ng" ]; then
    git clone -q https://github.com/cddmp/enum4linux-ng.git "${TOOLS_DIR}/enum4linux-ng"
    # Instalar dependencias de enum4linux-ng en el virtualenv (se hará después)
    log_ok "enum4linux-ng instalado en ${TOOLS_DIR}/enum4linux-ng"
else
    log_ok "enum4linux-ng ya instalado"
fi

# theHarvester (dentro del proyecto)
THEHARVESTER_DIR="${FAROSINT_DIR}/tools/theHarvester"
mkdir -p "${FAROSINT_DIR}/tools"
if [ ! -d "${THEHARVESTER_DIR}" ]; then
    git clone -q https://github.com/laramies/theHarvester.git "${THEHARVESTER_DIR}"
    log_ok "theHarvester instalado en ${THEHARVESTER_DIR}"
else
    log_ok "theHarvester ya instalado"
fi

# RustScan (descargar binario)
RUSTSCAN_DIR="${FAROSINT_DIR}/tools/rustscan"
mkdir -p "${RUSTSCAN_DIR}"
if [ ! -f "${RUSTSCAN_DIR}/rustscan" ]; then
    cd /tmp
    RUSTSCAN_URL="https://github.com/RustScan/RustScan/releases/latest/download/rustscan-2.3.0-linux_amd64.zip"
    wget -q "${RUSTSCAN_URL}" -O rustscan.zip 2>/dev/null || {
        # Intentar con .deb
        wget -q "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb" -O rustscan.deb 2>/dev/null && {
            dpkg -i rustscan.deb 2>/dev/null || apt-get -f install -y -qq 2>/dev/null
            cp /usr/bin/rustscan "${RUSTSCAN_DIR}/rustscan" 2>/dev/null || true
            rm -f rustscan.deb
        }
    }
    if [ -f rustscan.zip ]; then
        unzip -o -q rustscan.zip -d "${RUSTSCAN_DIR}" 2>/dev/null || true
        chmod +x "${RUSTSCAN_DIR}/rustscan" 2>/dev/null || true
        rm -f rustscan.zip
    fi
    log_ok "RustScan instalado (o intento de instalación)"
else
    log_ok "RustScan ya instalado"
fi

# Permisos
chown -R "${FAROSINT_USER}:${FAROSINT_USER}" "${TOOLS_DIR}"
chown -R "${FAROSINT_USER}:${FAROSINT_USER}" "${FAROSINT_DIR}/tools"

# ============================================================================
# PASO 8: CONFIGURAR ENTORNO PYTHON
# ============================================================================

log_step "Paso 7/12: Configurando entorno Python"

VENV_DIR="${FAROSINT_DIR}/farosint-env"

# Crear virtualenv
su - "${FAROSINT_USER}" -c "
    cd ${FAROSINT_DIR}
    python3 -m venv farosint-env
    source farosint-env/bin/activate
    pip install --upgrade pip setuptools wheel -q
    pip install -r requirements.txt -q
    echo '  Dependencias Python instaladas'
"
log_ok "Virtualenv creado y dependencias instaladas"

# ============================================================================
# PASO 9: CONFIGURAR BASH ENVIRONMENT
# ============================================================================

log_step "Paso 8/12: Configurando entorno de usuario"

# Agregar exports al .bashrc (solo si no existen)
BASHRC="${FAROSINT_HOME}/.bashrc"

grep -q "FAROSINT_HOME" "${BASHRC}" || {
    cat >> "${BASHRC}" << 'BASHRC_EOF'

# FAROSINT Environment
export FAROSINT_HOME="$HOME/FAROSINT"
export PATH="$FAROSINT_HOME/bin:$HOME/.local/bin:$PATH"
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
BASHRC_EOF
}
log_ok ".bashrc configurado (FAROSINT_HOME, Go, PATH)"

# Crear .xsession para xrdp
cat > "${FAROSINT_HOME}/.xsession" << 'EOF'
#!/bin/bash
exec openbox-session
EOF
chmod +x "${FAROSINT_HOME}/.xsession"
log_ok ".xsession creado (Openbox para xRDP)"

# ============================================================================
# PASO 10: CONFIGURAR DESKTOP (Openbox, tint2, jgmenu, LightDM)
# ============================================================================

log_step "Paso 9/12: Configurando entorno de escritorio"

# Openbox
OB_DIR="${FAROSINT_HOME}/.config/openbox"
mkdir -p "${OB_DIR}"
cp "${SYSTEM_DIR}/openbox/autostart" "${OB_DIR}/"
cp "${SYSTEM_DIR}/openbox/menu.xml" "${OB_DIR}/"
cp "${SYSTEM_DIR}/openbox/wallpaper-daemon.sh" "${OB_DIR}/"
cp "${SYSTEM_DIR}/openbox/rc.xml" "${OB_DIR}/"
chmod +x "${OB_DIR}/autostart" "${OB_DIR}/wallpaper-daemon.sh"
log_ok "Openbox configurado (autostart, menu, wallpaper daemon, rc.xml)"

# tint2
TINT2_DIR="${FAROSINT_HOME}/.config/tint2"
mkdir -p "${TINT2_DIR}"
cp "${SYSTEM_DIR}/tint2/tint2rc" "${TINT2_DIR}/"
log_ok "tint2 configurado (tema dark FAROSINT)"

# jgmenu
JGMENU_DIR="${FAROSINT_HOME}/.config/jgmenu"
mkdir -p "${JGMENU_DIR}"
cp "${SYSTEM_DIR}/jgmenu/jgmenurc" "${JGMENU_DIR}/"
cp "${SYSTEM_DIR}/jgmenu/farosint-menu.csv" "${JGMENU_DIR}/"
log_ok "jgmenu configurado (menú estilo Kali)"

# Menu popup script
cp "${SYSTEM_DIR}/farosint-menu-popup.sh" "${FAROSINT_HOME}/"
chmod +x "${FAROSINT_HOME}/farosint-menu-popup.sh"

# Desktop entries
DESKTOP_DIR="${FAROSINT_HOME}/.local/share/applications"
mkdir -p "${DESKTOP_DIR}"
cp "${SYSTEM_DIR}/desktop-entries/"*.desktop "${DESKTOP_DIR}/"
log_ok "Desktop entries instalados"

# ============================================================================
# PASO 11: BRANDING (wallpaper, avatar, logos)
# ============================================================================

log_step "Paso 10/12: Aplicando branding FAROSINT"

BRANDING_DIR="${SYSTEM_DIR}/branding"

# Wallpaper de escritorio
cp "${BRANDING_DIR}/Farosint_1920x1080.png" "${FAROSINT_HOME}/"
log_ok "Wallpaper copiado"

# Avatar / Logo
cp "${BRANDING_DIR}/Farosint_logo.png" "${FAROSINT_HOME}/.face"
cp "${BRANDING_DIR}/farosint_logo.png" "${FAROSINT_HOME}/"
log_ok "Avatar configurado (.face)"

# Logo BMP para xrdp
cp "${BRANDING_DIR}/Farosint.bmp" "${FAROSINT_HOME}/"
log_ok "Logo BMP copiado"

# LightDM - wallpaper de login
cp "${BRANDING_DIR}/Farosint_1920x1080.png" /usr/share/pixmaps/farosint-wallpaper.png

# LightDM - avatar AccountsService
mkdir -p /var/lib/AccountsService/icons
cp "${BRANDING_DIR}/Farosint_logo.png" /var/lib/AccountsService/icons/${FAROSINT_USER}

# AccountsService user config
mkdir -p /var/lib/AccountsService/users
cat > "/var/lib/AccountsService/users/${FAROSINT_USER}" << EOF
[User]
Icon=/var/lib/AccountsService/icons/${FAROSINT_USER}
EOF

# LightDM greeter config
cp "${SYSTEM_DIR}/lightdm/lightdm-gtk-greeter.conf" /etc/lightdm/lightdm-gtk-greeter.conf
log_ok "LightDM configurado (wallpaper + avatar)"

# ============================================================================
# PASO 12: CONFIGURAR xRDP BRANDING
# ============================================================================

log_step "Paso 11/12: Configurando xRDP branding"

# Agregar usuario al grupo ssl-cert
usermod -aG ssl-cert "${FAROSINT_USER}"

# Ejecutar script de branding xrdp
if [ -f "${SYSTEM_DIR}/xrdp/setup_xrdp_branding.py" ]; then
    python3 "${SYSTEM_DIR}/xrdp/setup_xrdp_branding.py"
    log_ok "xRDP branding aplicado (logo FAROSINT, título, solo sesión Xorg)"
else
    log_warn "Script de branding xrdp no encontrado"
fi

# ============================================================================
# PASO 13: INSTALAR LAUNCHERS
# ============================================================================

log_step "Paso 12/12: Instalando launchers y permisos finales"

# Copiar launchers a /usr/local/bin
cp "${SYSTEM_DIR}/launchers/farosint" /usr/local/bin/
cp "${SYSTEM_DIR}/launchers/farosint-simple" /usr/local/bin/
cp "${SYSTEM_DIR}/launchers/farosint-advanced" /usr/local/bin/
cp "${SYSTEM_DIR}/launchers/farosint-cli" /usr/local/bin/
chmod +x /usr/local/bin/farosint*
log_ok "Launchers instalados en /usr/local/bin/"

# Crear directorios necesarios de la aplicación
mkdir -p "${FAROSINT_DIR}/output"
mkdir -p "${FAROSINT_DIR}/logs"
mkdir -p "${FAROSINT_DIR}/engine/cache"

# Permisos finales - todo propiedad de farosint
chown -R "${FAROSINT_USER}:${FAROSINT_USER}" "${FAROSINT_HOME}"

# Asegurar que el directorio .config tiene permisos correctos
chmod 700 "${FAROSINT_HOME}/.config"

log_ok "Permisos configurados"

# ============================================================================
# RESUMEN FINAL
# ============================================================================

log_step "INSTALACIÓN COMPLETADA"

echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║          FAROSINT - Instalación Exitosa          ║"
echo "  ╠══════════════════════════════════════════════════╣"
echo "  ║                                                  ║"
echo "  ║  Usuario:    ${FAROSINT_USER}                          ║"
echo "  ║  Hostname:   ${HOSTNAME_NEW}              ║"
echo "  ║                                                  ║"
echo "  ║  Dashboard:  http://localhost:5000               ║"
echo "  ║  SSH:        puerto 22                           ║"
echo "  ║  RDP:        puerto 3389                         ║"
echo "  ║                                                  ║"
echo "  ║  Iniciar dashboard:                              ║"
echo "  ║    farosint start                                ║"
echo "  ║                                                  ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

echo ""
echo "Herramientas instaladas:"
echo "  - Nmap, DNSRecon, WhatWeb, Gobuster, SNMP"
echo "  - Subfinder, Nuclei, Httpx (Go)"
echo "  - Amass ${AMASS_VERSION}"
echo "  - Nikto, enum4linux-ng, theHarvester, RustScan"
echo ""
echo "Desktop:"
echo "  - Openbox + LightDM + tint2 + jgmenu"
echo "  - Wallpaper FAROSINT, avatar, branding completo"
echo "  - xRDP con logo y título FAROSINT"
echo ""
echo -e "${YELLOW}>>> Reiniciar el sistema para aplicar todos los cambios <<<${NC}"
echo -e "${YELLOW}    sudo reboot${NC}"
echo ""
