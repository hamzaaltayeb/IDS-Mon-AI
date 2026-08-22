-- =============================================================================
-- Intelligent Network Security Monitoring System using AI (AI-NSMS)
-- Database: PostgreSQL Schema & Data Definition Language (DDL)
-- =============================================================================

DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS detections CASCADE;
DROP TABLE IF EXISTS network_flows CASCADE;
DROP TABLE IF EXISTS system_logs CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'SECURITY_ANALYST' CHECK (role IN ('ADMIN', 'SECURITY_ANALYST')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE network_flows (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    destination_port INTEGER NOT NULL,
    flow_duration DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    total_flow_size DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    average_packet_size DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    std_packet_size DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    packet_count INTEGER NOT NULL DEFAULT 0,
    average_inter_arrival_time DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    maximum_inter_arrival_time DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    packets_per_second DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    bytes_per_second DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE detections (
    id SERIAL PRIMARY KEY,
    flow_id INTEGER NOT NULL REFERENCES network_flows(id) ON DELETE CASCADE,
    prediction VARCHAR(20) NOT NULL CHECK (prediction IN ('ATTACK', 'NORMAL')),
    attack_type VARCHAR(50) NOT NULL CHECK (attack_type IN ('NORMAL', 'DDOS', 'PORT_SCAN', 'BRUTE_FORCE', 'UNKNOWN')),
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    threat_score INTEGER NOT NULL DEFAULT 0 CHECK (threat_score >= 0 AND threat_score <= 100),
    severity VARCHAR(20) NOT NULL DEFAULT 'LOW' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    indicators TEXT,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'ACKNOWLEDGED', 'RESOLVED')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP
);

CREATE TABLE system_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_network_flows_captured_at ON network_flows(captured_at);
CREATE INDEX idx_network_flows_source_ip ON network_flows(source_ip);
CREATE INDEX idx_detections_attack_type ON detections(attack_type);
CREATE INDEX idx_detections_severity ON detections(severity);
CREATE INDEX idx_detections_detected_at ON detections(detected_at);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_system_logs_user_id ON system_logs(user_id);
CREATE INDEX idx_system_logs_created_at ON system_logs(created_at);
