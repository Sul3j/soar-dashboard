import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import Optional
from pydentic import BaseModel, Field

# ENVIRONMENT CONFIGURATION

# Configuration from environment variables
PROXMOX_HOST = os.getenv("PROXMOX_HOST")
PROXMOX_TOKEN = os.getenv("PROXMOX_TOKEN")
PROXMOX_NODE = os.getenv("PROXMOX_NODE")
DATABASE_URL = os.getenv("DATABASE_URL")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")

# For testing and development, we can enable a demo mode that simulates responses without making real API calls.
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"


# APPLICATION SETUP

app = FastAPI(
    title="SOAR API",
    description="API for Security Orchestration, Automation, and Response (SOAR) system to manage alerts and automate responses.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DATAMODEL DEFINITIONS

# Details of a new alert from the monitoring agent.
class AlertCreate(BaseModel):
    event: str = Field(..., example="SSH_BRUTE_FORCE")
    attacker_ip: str = Field(..., example="198.51.100.42")
    target_vm_id: int = Field(..., example=111)
    target_vm_name: str = Field(..., example="ProjektStudia")
    severity: str = Field(default="medium", example="high")
    description: Optional[str] = None

# Request to block an IP address
class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block"
    permanent: bool = False

# Request to resolve the alert.
class ResolveRequest(BaseModel):
    notes: Optional[str] = None

# Response after creating the alert.
class AlertResponse(BaseModel):
    alert_id: int
    status: str
    action_taken: str
    threat_score: int

# The result of an IP check against threat intelligence databases. 
class ThreatIntelResult(BaseModel):
    ip: str
    abuseipdb_score: int = 0
    virustotal_malicious: int = 0
    total_threat_score: int = 0
    recomendation: str = ""

# STORAGE SIMULATION

alerts_db: list[dict] = []
blocked_ips_db: list[dict] = []
vm_statuses: dict[int, dict] = {
    111: {
        "vm_id": 111,
        "vm_name": "ProjektStudia",
        "vlan": 10,
        "status": "production",
        "last_incident_at": None,
    },
}