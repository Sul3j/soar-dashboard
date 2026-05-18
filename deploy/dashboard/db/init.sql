CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    attacker_ip INET NOT NULL,
    target_vm_id INTEGER,
    target_vm_name VARCHAR(100),
    abuse_score INTEGER DEFAULT 0,
    threat_score INTEGER DEFAULT 0,
    severity VARCHAR(20) DEFAULT 'medium',
    action_taken VARCHAR(50),
    vlan_before INTEGER,
    vlan_after INTEGER,
    geo_country VARCHAR(100),
    geo_city VARCHAR(100),
    geo_lat DECIMAL(10, 6),
    geo_lon DECIMAL(10, 6),
    isp VARCHAR(200),
    source VARCHAR(50) DEFAULT 'ssh_monitor',
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by VARCHAR(100),
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip INET NOT NULL UNIQUE,
    reason VARCHAR(200),
    source VARCHAR(50),
    blocked_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    permanent BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS vm_status (
    vm_id INTEGER PRIMARY KEY,
    vm_name VARCHAR(100),
    current_vlan INTEGER,
    status VARCHAR(20) DEFAULT 'production',
    last_incident_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(event_type);
CREATE INDEX IF NOT EXISTS idx_incidents_resolved ON incidents(resolved);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);

CREATE OR REPLACE VIEW daily_stats AS
SELECT
    DATE(created_at) AS day,
    COUNT(*) AS total_incidents,
    COUNT(DISTINCT attacker_ip) AS unique_attackers,
    COUNT(*) FILTER (WHERE action_taken = 'ISOLATED') AS isolations,
    COUNT(*) FILTER (WHERE resolved = TRUE) AS resolved,
    AVG(abuse_score) AS avg_abuse_score
FROM incidents
GROUP BY DATE(created_at)
ORDER BY day DESC;

CREATE OR REPLACE VIEW top_attackers AS
SELECT
    attacker_ip,
    COUNT(*) AS attack_count,
    MAX(abuse_score) AS max_abuse_score,
    MAX(created_at) AS last_seen,
    array_agg(DISTINCT event_type) AS event_types
FROM incidents
GROUP BY attacker_ip
ORDER BY attack_count DESC
LIMIT 50;

INSERT INTO vm_status (vm_id, vm_name, current_vlan, status) VALUES
    (111, 'ProjektStudia', 10, 'production')
ON CONFLICT (vm_id) DO NOTHING;
