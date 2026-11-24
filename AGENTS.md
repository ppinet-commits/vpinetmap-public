# AGENTS.md — VPiNetmap (Multi-Client VPN Gateway & Appliance)

Plataforma unificada para mantener múltiples túneles VPN conectados 24/7 en un host o VM Linux,
resolviendo colisiones de subredes idénticas mediante Network Namespaces aislados y NETMAP bidireccional
de iptables. Administrable vía interfaz web moderna HTTPS con usuarios, roles, 2FA y auditoría de tráfico.

Este archivo es el documento maestro de traspaso técnico: cualquier agente de IA (Antigravity, Claude Code,
Gemini CLI, OpenCode) debe poder entender la arquitectura completa y retomar el desarrollo con esta información.

---

## 1. Reglas para Agentes

- **Seguridad y Privacidad:** Nunca incluir contraseñas, claves privadas, archivos de secreto (`.env`, `.wg`, `.ovpn`), certificados privados o tokens en el repositorio.
- **Configuraciones de Ejemplo:** El repositorio público contiene plantillas genéricas en `examples/clientes/` y `examples/secrets/`. Los secretos reales en producción residen exclusivamente en `/etc/vpnhub/secrets/` (root 600).
- **Acceso Administrativo:** En despliegues reales, la administración remota de la máquina Linux se realiza mediante llaves SSH autorizadas.
- **Cero Dependencias Externas en Frontend:** La interfaz web (`panel/index.html` y `panel/login.html`) debe mantenerse en HTML5 / CSS3 / Vanilla JS puro, sin frameworks pesados ni CDNs externos, para garantizar operación 100% offline y en redes aisladas.
- **Validación previa a commits:**
  - Sintaxis de scripts Bash: `bash -n bin/hubctl` e `install.sh`.
  - Sintaxis de Python: `python3 -m py_compile panel/hubnets.py panel/vpnhub-panel.py bin/hubtraffic`.
- **Actualizar este archivo:** Al implementar nuevas funciones, refactorizar o resolver bugs, actualizar este archivo en la sección correspondiente.

---

## 2. Estructura del Repositorio y Destinos en el Sistema Linux

| Repositorio | Destino en el Sistema | Descripción |
|---|---|---|
| `bin/hubctl` | `/usr/local/sbin/hubctl` | Bash: orquestador de namespaces, veth, iptables y clientes VPN en primer plano |
| `bin/hubtraffic` | `/usr/local/sbin/hubtraffic` | Python: colector conntrack de eventos de tráfico, base SQLite y CLI de auditoría |
| `bin/vpnhub-ipsec-updown` | `/usr/local/sbin/vpnhub-ipsec-updown` | Bash: asignación dinámica de VIP y rutas para túneles strongSwan IKEv2 XFRM |
| `bin/vpnhub-saml-auth` | `/usr/local/sbin/vpnhub-saml-auth` | Python (Playwright headless): autenticación SAML y Cisco Duo SSO para AnyConnect |
| `panel/hubnets.py` | `/opt/vpnhub-panel/hubnets.py` | Python: backend de redes, cálculo NETMAP, rutas del kernel y persistencia de configs |
| `panel/vpnhub-panel.py` | `/opt/vpnhub-panel/vpnhub-panel.py` | Python: servidor HTTPS nativo, API REST, sesiones web, 2FA y control de procesos |
| `panel/index.html` | `/opt/vpnhub-panel/index.html` | Frontend SPA: tablero web principal, cuadrícula/lista, modales de tráfico y usuarios |
| `panel/login.html` | `/opt/vpnhub-panel/login.html` | Pantalla de login dedicada con soporte 2FA (TOTP y Duo Push) y «recordar dispositivo» |
| `panel/favicon.svg` | `/opt/vpnhub-panel/favicon.svg` | Favicon e identidad visual SVG minimalista transparente |
| `systemd/vpnhub@.service` | `/etc/systemd/system/` | Servicio systemd para supervisión continua de túneles (`Restart=always`) |
| `systemd/vpnhub-dns@.service` | `/etc/systemd/system/` | Instancia dnsmasq interna para túneles con DNS corporativo split |
| `systemd/vpnhub-sync.{service,timer}` | `/etc/systemd/system/` | Timer de sincronización periódica de rutas dinámicas (cada 30s) |
| `systemd/vpnhub-traffic.service` | `/etc/systemd/system/` | Servicio de streaming continuo de conntrack hacia SQLite |
| `systemd/vpnhub-panel.service` | `/etc/systemd/system/` | Servicio del panel web HTTPS |
| `examples/clientes/` | `/etc/vpnhub/clientes/` | Plantillas `.conf` de configuración para cada tecnología soportada |
| `examples/secrets/` | `/etc/vpnhub/secrets/` | Plantillas de credenciales y secretos `.env`, `.wg`, `.ovpn` |
| `proxmox/crear-vm-vpnhub.sh` | (Script host PVE) | Automatización para desplegar la máquina virtual base en Proxmox VE |
| `install.sh` | `/root/vpnhub/install.sh` | Instalador todo-en-uno para Debian 12 / 13 y Ubuntu Server |

En un host desplegado en producción, el sistema crea además:
- `/etc/vpnhub/secrets/` (archivos con permisos `0600` de credenciales y claves privadas).
- `/etc/vpnhub/users.json` (base de usuarios del panel, roles, hashes y 2FA).
- `/var/log/vpnhub/traffic.db` (base SQLite con eventos conntrack y métricas de red).
- `/var/log/vpnhub/audit.jsonl` (auditoría estructurada de accesos y eventos administrativos).
- `/run/vpnhub/` (estado volátil en RAM, sockets, locks y mapeos de red activos).

---

## 3. Arquitectura de Red y Aislamiento

```
Equipo LAN ──(Ruta 10.192.0.0/10)──► Host VPiNetmap (IP LAN)
   Namespace Principal (main):
     - Tabla de rutas: Red virtual 10.(200+ID).X.0/24 ──► veth vh<ID> (100.64.ID.1/30)
     - SNAT a 100.64.ID.1 en interfaz vh<ID>
     - Regla FORWARD: DROP vh+ ──► vh+ (los clientes no se ven entre sí)
   
   Namespace del Cliente (vpn-<cliente>):
     - Interfaz vn<ID> (100.64.ID.2/30) con default gateway 100.64.ID.1
     - iptables NETMAP PREROUTING: virtual 10.(200+ID).X.Y ──► real cliente
     - iptables MASQUERADE POSTROUTING hacia la interfaz del túnel
     - FORWARD: DROP de tráfico originado en el túnel hacia el hub (tráfico unidireccional seguro)
     - Túnel activo (tun<ID>, ppp<ID>, wg<ID>, ipsec<ID>) ──► Red remota
```

### Convención de Redes Virtuales (NETMAP)
- **Rango virtual:** Cliente con ID $N$ ($1 \le N \le 55$) recibe la subred virtual `10.(200+N).X.Y`.
- **Mapeo 1:1:** Conserva el 3° y 4° octeto de la red real original (ejemplo: red remota `192.168.0.50` en cliente ID 2 se accede en `10.202.0.50`).
- **Enrutamiento de la LAN:** El router de la red local solo necesita una ruta estática `10.192.0.0/10` apuntando a la IP del host VPiNetmap para acceder a todos los clientes sin tocar configuraciones en los extremos remotos.

---

## 4. Tecnologías VPN Soportadas

1. **Fortinet FortiGate SSL VPN (`forti`):**
   - Motor: `openfortivpn`.
   - Soporte para validación de certificado sha256 (`TRUSTED_CERT`), OTP dinámico y lectura automática de rutas inyectadas por el firewall.
2. **Fortinet FortiGate IPsec Dialup (`forti_ipsec`):**
   - **IKEv2 (Modo moderno):** strongSwan (`charon-systemd`) con interfaz XFRM dedicada `ipsec<ID>`, autenticación PSK y EAP-MSCHAPv2, y script `vpnhub-ipsec-updown` para instalación de VIP y rutas.
   - **IKEv1 (Modo legacy):** `vpnc` con modo agresivo, PSK, XAuth y grupos DH configurables (`DHGROUP`).
3. **Cisco AnyConnect / OpenConnect (`anyconnect`):**
   - Motor: `openconnect` + `vpnc-script`.
   - Autenticación estándar (usuario/contraseña/OTP) y soporte para **SAML / Cisco Duo SSO Universal Prompt** desatendido mediante `bin/vpnhub-saml-auth` (Playwright Chromium headless).
4. **WireGuard (`wireguard`):**
   - Motor: `wireguard-tools` dentro del namespace.
   - Supervisión activa de endpoints dinámicos (DDNS tipo MikroTik Back-To-Home BTH) con re-resolución DNS y reinicio automático si expira el handshake.
   - Encapsulamiento de rutas `AllowedIPs = 0.0.0.0/0` aislado en el namespace.
5. **OpenVPN (`openvpn`):**
   - Motor: `openvpn 2.6+`.
   - Soporte para perfiles `.ovpn` unificados, autenticación por usuario/contraseña y claves privadas cifradas vía `--askpass`.
6. **L2TP/IPsec (`l2tp`):**
   - Motor: strongSwan + `xl2tpd` aislados por namespace mediante `/etc/netns/vpn-<c>/`.

---

## 5. Módulos del Sistema

### `hubctl` (CLI de Control)
- Comandos: `hubctl up|down|status|cert|routes|maps <cliente>` · `hubctl run <cliente>` (invocado por systemd) · `hubctl live` · `hubctl audit`.
- Gestiona el ciclo de vida de los namespaces, interfaces veth y los clientes VPN en primer plano para permitir reinicio automático de systemd ante caídas.

### `hubnets` (Motor de Enrutamiento y Mapeos)
- Gestiona mapeos manuales y dinámicos (`AUTO_MAP=1`), resolución de conflictos de subredes, configuración de iptables NETMAP y sincronización de DNS.
- Valida solapamientos contra la LAN local y el rango reservado `100.64.0.0/16`.

### `hubtraffic` (Auditoría conntrack y Estadísticas)
- Captura en tiempo real eventos del kernel vía Netfilter conntrack (`conntrack -E -e NEW,DESTROY`).
- Almacena en SQLite (`traffic.db`) sesiones discriminadas por usuario, origen, VPN, servicio (RDP, Web, SSH, SQL) y volumen de bytes.
- Genera líneas de tiempo de 24 horas y reportes exportables en CSV.

### DNS Sintético y Portal Cautivo
- **dnsmasq integrado:** Genera automáticamente resoluciones del tipo `<IP_real>.<alias>` y `<IP_real>.<alias>.hub` hacia la IP virtual asignada.
- **Portal de Conflicto (Puerto 80):** Cuando dos túneles contienen la misma subred real (ej. `192.168.0.0/24`), el tráfico HTTP se intercepta para permitir al operador seleccionar interactivamente qué túnel priorizar en el enrutador.

### Servidor WireGuard Road Warrior
- Instancia `wg0` en el host (rango `10.99.0.1/24`, puerto UDP 51820).
- Permite a usuarios y técnicos conectarse de forma remota y acceder directamente a los túneles del hub descargando su perfil individual `.conf` desde el panel web.

---

## 6. Procedimiento de Pruebas y Desarrollo

1. **Instalación de entorno de pruebas:**
   ```bash
   sudo bash install.sh
   ```
2. **Validar estado de servicios:**
   ```bash
   sudo systemctl status vpnhub-panel vpnhub-traffic vpnhub-sync.timer
   ```
3. **Comprobar túneles y redes:**
   ```bash
   sudo hubctl status
   sudo hubctl live
   sudo hubtraffic audit today
   ```
4. **Verificación del Panel Web:**
   - Acceso HTTPS en el puerto configurado (por defecto `:8443`).
   - Crear usuarios de prueba con `vpnhub-panel useradd <usuario> [--admin]`.
