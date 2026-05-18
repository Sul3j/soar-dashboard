from datetime import datetime
from typing import Optional
from pydentic import BaseModel, Field


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

