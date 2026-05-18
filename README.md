# SOAR Dashboard

System SIEM/SOAR Lite do monitorowania i reagowania na incydenty bezpieczeństwa.

## Stos technologiczny
- **Backend:** Python + FastAPI
- **Frontend:** Angular 18 + Angular Material
- **Monitoring:** Python daemon analizujący auth.log
- **Orkiestracja:** n8n (webhook workflows)
- **Infrastruktura:** Proxmox VE + VLAN isolation
- **Powiadomienia:** Discord Bot

## Uruchomienie (dev)
\`\`\`bash
docker-compose -f docker-compose.dev.yml up --build
\`\`\`
