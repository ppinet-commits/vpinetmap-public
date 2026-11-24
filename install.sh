#!/usr/bin/env bash
# ==============================================================================
# VPNHub — Instalador automatizado para Debian 12 / 13 y Ubuntu
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
die() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Este script debe ejecutarse con permisos de root (sudo bash install.sh)."

log "Iniciando instalación de VPNHub..."

# 1. Paquetes requeridos
log "Instalando paquetes y clientes VPN..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q \
    openfortivpn \
    openconnect \
    vpnc-scripts \
    openvpn \
    wireguard \
    wireguard-tools \
    strongswan \
    strongswan-charon-systemd \
    xl2tpd \
    ppp \
    iptables \
    conntrack \
    dnsmasq \
    bind9-dnsutils \
    python3 \
    python3-pip \
    curl \
    openssl \
    sqlite3

ok "Paquetes instalados correctamente."

# 2. Estructura de directorios
log "Configurando directorios en /etc/vpnhub, /opt/vpnhub-panel y /var/log/vpnhub..."
install -d -m 755 /usr/local/sbin
install -d -m 755 /opt/vpnhub-panel
install -d -m 755 /etc/vpnhub/clientes
install -d -m 700 /etc/vpnhub/secrets
install -d -m 755 /var/log/vpnhub
install -d -m 755 /run/vpnhub

# 3. Copiar ejecutables y panel
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "Instalando binarios en /usr/local/sbin..."
install -m 755 "$DIR/bin/hubctl" /usr/local/sbin/hubctl
install -m 755 "$DIR/bin/hubtraffic" /usr/local/sbin/hubtraffic
install -m 755 "$DIR/bin/vpnhub-ipsec-updown" /usr/local/sbin/vpnhub-ipsec-updown
install -m 755 "$DIR/bin/vpnhub-saml-auth" /usr/local/sbin/vpnhub-saml-auth

log "Instalando panel web en /opt/vpnhub-panel..."
install -m 755 "$DIR/panel/hubnets.py" /opt/vpnhub-panel/hubnets.py
install -m 755 "$DIR/panel/vpnhub-panel.py" /opt/vpnhub-panel/vpnhub-panel.py
install -m 644 "$DIR/panel/index.html" /opt/vpnhub-panel/index.html
install -m 644 "$DIR/panel/login.html" /opt/vpnhub-panel/login.html
install -m 644 "$DIR/panel/favicon.svg" /opt/vpnhub-panel/favicon.svg

# Enlaces simbólicos convenientes
ln -sf /opt/vpnhub-panel/hubnets.py /usr/local/sbin/hubnets
ln -sf /opt/vpnhub-panel/vpnhub-panel.py /usr/local/sbin/vpnhub-panel

# 4. Servicios systemd
log "Instalando unidades systemd..."
cp "$DIR"/systemd/*.service /etc/systemd/system/
cp "$DIR"/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload

# 5. Parámetros del Kernel (Forwarding y Conntrack Accounting)
log "Configurando sysctl (IP forwarding y auditoría conntrack)..."
cat > /etc/sysctl.d/99-vpnhub.conf <<EOF
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_timestamp = 1
EOF
sysctl -p /etc/sysctl.d/99-vpnhub.conf >/dev/null 2>&1 || true

# 6. Certificado TLS autofirmado si no existe
if [[ ! -f /etc/vpnhub/panel.crt || ! -f /etc/vpnhub/panel.key ]]; then
    log "Generando certificado TLS autofirmado para el panel HTTPS (:8443)..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/vpnhub/panel.key \
        -out /etc/vpnhub/panel.crt \
        -subj "/CN=vpnhub.hub/O=VPNHub/OU=Gateway" >/dev/null 2>&1
    chmod 600 /etc/vpnhub/panel.key
    ok "Certificado TLS generado."
fi

# 7. Servidor WireGuard Road Warrior integrado
if [[ ! -f /etc/wireguard/wg0.conf ]]; then
    log "Configurando servidor WireGuard Road Warrior (10.99.0.1/24, UDP 51820)..."
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
    wg_priv=$(wg genkey)
    wg_pub=$(echo "$wg_priv" | wg pubkey)
    echo "$wg_pub" > /etc/wireguard/server_public.key
    chmod 644 /etc/wireguard/server_public.key

    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = $wg_priv
EOF
    chmod 600 /etc/wireguard/wg0.conf
    systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || true
    ok "Servidor Road Warrior configurado."
fi

# 8. Activar timers y servicios
log "Iniciando servicios del sistema..."
systemctl enable --now vpnhub-sync.timer >/dev/null 2>&1 || true
systemctl enable --now vpnhub-traffic.service >/dev/null 2>&1 || true

# 9. Usuario inicial
if [[ ! -f /etc/vpnhub/users.json ]]; then
    log "Configurando usuario inicial 'admin' con contraseña temporal 'admin'..."
    /usr/local/sbin/vpnhub-panel init-default-admin >/dev/null 2>&1 || true
    ok "Usuario 'admin' creado exitosamente."
fi

systemctl enable --now vpnhub-panel.service >/dev/null 2>&1 || true

# 10. Detección de IP LAN
lan_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' || echo "127.0.0.1")

echo ""
echo -e "${GREEN}========================================================================${NC}"
echo -e "${GREEN}  ¡VPiNetmap se instaló y configuró exitosamente!                       ${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo ""
echo -e "  🌐 Panel Web HTTPS: ${BLUE}https://${lan_ip}:8443${NC} (o https://vpnhub.hub:8443)"
echo -e "  👤 Usuario:        ${YELLOW}admin${NC}"
echo -e "  🔑 Contraseña:     ${YELLOW}admin${NC} (se solicitará cambio obligatorio en el primer login)"
echo ""
echo -e "  Para administrar VPNs y redes desde la terminal:"
echo -e "    ${BLUE}sudo hubctl status${NC}           # Ver estado de los túneles"
echo -e "    ${BLUE}sudo hubnets list <cliente>${NC}  # Ver redes mapeadas"
echo -e "    ${BLUE}sudo hubctl live${NC}             # Ver tráfico en vivo en tiempo real"
echo -e "    ${BLUE}sudo hubctl audit${NC}            # Auditoría de accesos y sesiones"
echo ""
