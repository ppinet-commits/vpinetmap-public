# GEMINI.md — VPiNetmap (Multi-Client VPN Gateway & Appliance)

Contexto de desarrollo para Gemini CLI en el proyecto VPiNetmap Open Source.

@./AGENTS.md

## Pautas Rápidas
- Consultar siempre `AGENTS.md` para entender la arquitectura de namespaces y NETMAP.
- Probar cambios con `bash -n bin/hubctl` y `python3 -m py_compile panel/*.py`.
- Si se modifican archivos del panel en un host activo: `sudo systemctl restart vpnhub-panel`.
- Al finalizar cambios significativos, actualizar la documentación técnica correspondiente.
