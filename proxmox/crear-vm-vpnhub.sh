#!/usr/bin/env bash
# Crea la VM "vpnhub" en Proxmox VE 8+ a partir de la imagen cloud de Debian 13 (kernel completo).
# Ejecutar como root en la shell del nodo Proxmox.
#
# Uso (ejemplo):
#   bash crear-vm-vpnhub.sh                                    (IP por DHCP, por defecto)
#   IP=192.168.0.50/24 GW=192.168.0.1 bash crear-vm-vpnhub.sh  (IP fija)
#
# Variables opcionales: VMID, NAME, STORAGE, BRIDGE, DNS, CIUSER, SSHKEY_PUB
set -euo pipefail

VMID="${VMID:-900}"
NAME="${NAME:-vpnhub}"
STORAGE="${STORAGE:-local-lvm}"
BRIDGE="${BRIDGE:-vmbr0}"
IP="${IP:-dhcp}"
GW="${GW:-}"
if [[ "$IP" == "dhcp" ]]; then IPCONFIG="ip=dhcp"; else IPCONFIG="ip=${IP},gw=${GW:?Con IP fija definí GW}"; fi
DNS="${DNS:-1.1.1.1}"
CIUSER="${CIUSER:-admin}"
DISK_SIZE="${DISK_SIZE:-16G}"
# Clave pública SSH (por defecto toma ~/.ssh/id_ed25519.pub o id_rsa.pub si existe)
default_key=""
if [[ -f ~/.ssh/id_ed25519.pub ]]; then
  default_key=$(cat ~/.ssh/id_ed25519.pub)
elif [[ -f ~/.ssh/id_rsa.pub ]]; then
  default_key=$(cat ~/.ssh/id_rsa.pub)
fi
SSHKEY_PUB="${SSHKEY_PUB:-$default_key}"

# Imagen "generic" (no "genericcloud"): trae el kernel completo con ppp, tun, wireguard, xfrm.
IMG_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2"
IMG="/var/lib/vz/template/debian-13-generic-amd64.qcow2"

command -v qm >/dev/null || { echo "Esto se ejecuta en un nodo Proxmox (falta 'qm')."; exit 1; }
if qm status "$VMID" >/dev/null 2>&1; then
  echo "Ya existe una VM con ID $VMID. Usá otro: VMID=901 ..."; exit 1
fi

if [[ ! -f "$IMG" ]]; then
  echo ">> Descargando imagen Debian 13..."
  mkdir -p "$(dirname "$IMG")"
  wget -q --show-progress -O "$IMG.part" "$IMG_URL"
  mv "$IMG.part" "$IMG"
fi

KEYFILE="$(mktemp)"; trap 'rm -f "$KEYFILE"' EXIT
echo "$SSHKEY_PUB" > "$KEYFILE"

echo ">> Creando VM $VMID ($NAME)..."
qm create "$VMID" \
  --name "$NAME" \
  --ostype l26 \
  --cores 2 --cpu host \
  --memory 2048 \
  --scsihw virtio-scsi-single \
  --net0 "virtio,bridge=${BRIDGE},firewall=0" \
  --agent enabled=1 \
  --serial0 socket --vga serial0 \
  --onboot 1 \
  --description "VPiNetmap - Multi-Client VPN Gateway & Appliance (Namespaces + NETMAP)"

qm set "$VMID" --scsi0 "${STORAGE}:0,import-from=${IMG},discard=on,ssd=1,iothread=1"
qm disk resize "$VMID" scsi0 "$DISK_SIZE"
qm set "$VMID" --ide2 "${STORAGE}:cloudinit" --boot order=scsi0
qm set "$VMID" \
  --ciuser "$CIUSER" \
  --sshkeys "$KEYFILE" \
  --ipconfig0 "$IPCONFIG" \
  --nameserver "$DNS" \
  --ciupgrade 1

echo ">> Iniciando VM..."
qm start "$VMID"

cat <<EOF

Listo. En 1-2 minutos la VM arranca y cloud-init aplica IP y clave.
MAC de la VM (para reservar la IP en el DHCP): $(qm config "$VMID" | sed -n 's/^net0: virtio=\([^,]*\).*/\1/p')
IP asignada: mirala en el router o, cuando corra el agente: qm guest cmd $VMID network-get-interfaces
Probá desde la PC:   ssh ${CIUSER}@<IP>
Después, dentro de la VM:  sudo apt install -y qemu-guest-agent && sudo systemctl enable --now qemu-guest-agent
EOF
