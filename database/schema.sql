CREATE DATABASE IF NOT EXISTS homenet_sentinel
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE homenet_sentinel;

CREATE TABLE IF NOT EXISTS admin_users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_admin_users_username (username),
    INDEX idx_admin_users_active (is_active)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS devices (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    mac_address VARCHAR(17) NULL,
    hostname VARCHAR(255) NULL,
    vendor VARCHAR(255) NULL,
    device_type VARCHAR(100) NULL,

    status ENUM('online', 'offline', 'unknown')
        NOT NULL DEFAULT 'unknown',

    trusted BOOLEAN NOT NULL DEFAULT FALSE,

    latency_ms DECIMAL(10,2) NULL,

    first_seen DATETIME NULL,
    last_seen DATETIME NULL,

    discovery_source VARCHAR(100) NULL,
    discovery_confidence DECIMAL(5,2) NULL,

    hostname_source VARCHAR(100) NULL,
    vendor_source VARCHAR(100) NULL,
    device_type_source VARCHAR(100) NULL,

    is_estimated BOOLEAN NOT NULL DEFAULT FALSE,

    notes TEXT NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_devices_mac_address (mac_address),

    INDEX idx_devices_status (status),
    INDEX idx_devices_trusted (trusted),
    INDEX idx_devices_last_seen (last_seen),
    INDEX idx_devices_hostname (hostname)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS device_ips (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    device_id BIGINT UNSIGNED NOT NULL,

    ip_address VARCHAR(45) NOT NULL,
    address_family ENUM('ipv4', 'ipv6') NOT NULL,

    is_current BOOLEAN NOT NULL DEFAULT TRUE,

    first_seen DATETIME NULL,
    last_seen DATETIME NULL,

    source VARCHAR(100) NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_device_ips_device_ip (device_id, ip_address),

    INDEX idx_device_ips_ip (ip_address),
    INDEX idx_device_ips_current (is_current),

    CONSTRAINT fk_device_ips_device
        FOREIGN KEY (device_id)
        REFERENCES devices(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS device_ports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    device_id BIGINT UNSIGNED NOT NULL,

    port_number INT UNSIGNED NOT NULL,
    protocol ENUM('tcp', 'udp') NOT NULL,

    state VARCHAR(30) NULL,
    service VARCHAR(100) NULL,
    product VARCHAR(255) NULL,
    version VARCHAR(255) NULL,

    first_seen DATETIME NULL,
    last_seen DATETIME NULL,

    source VARCHAR(100) NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_device_ports_device_port_protocol
        (device_id, port_number, protocol),

    INDEX idx_device_ports_port (port_number),
    INDEX idx_device_ports_state (state),

    CONSTRAINT fk_device_ports_device
        FOREIGN KEY (device_id)
        REFERENCES devices(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS device_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    device_id BIGINT UNSIGNED NULL,

    event_type VARCHAR(100) NOT NULL,
    severity ENUM('info', 'warning', 'critical')
        NOT NULL DEFAULT 'info',

    message TEXT NOT NULL,

    event_data JSON NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_device_events_device (device_id),
    INDEX idx_device_events_type (event_type),
    INDEX idx_device_events_severity (severity),
    INDEX idx_device_events_created (created_at),

    CONSTRAINT fk_device_events_device
        FOREIGN KEY (device_id)
        REFERENCES devices(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS scan_runs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,

    status ENUM('running', 'completed', 'failed')
        NOT NULL DEFAULT 'running',

    subnet VARCHAR(100) NULL,

    devices_found INT UNSIGNED NOT NULL DEFAULT 0,

    error_message TEXT NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_scan_runs_status (status),
    INDEX idx_scan_runs_started (started_at),
    INDEX idx_scan_runs_completed (completed_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS settings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    setting_key VARCHAR(100) NOT NULL,
    setting_value TEXT NULL,

    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_settings_key (setting_key)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS blocked_devices (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    device_id BIGINT UNSIGNED NOT NULL,

    block_type VARCHAR(50) NOT NULL,

    provider VARCHAR(100) NULL,

    provider_rule_id VARCHAR(255) NULL,

    status ENUM('requested', 'active', 'failed', 'removed')
        NOT NULL DEFAULT 'requested',

    reason VARCHAR(255) NULL,

    blocked_at DATETIME NULL,
    unblocked_at DATETIME NULL,

    error_message TEXT NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_blocked_devices_device (device_id),
    INDEX idx_blocked_devices_status (status),

    CONSTRAINT fk_blocked_devices_device
        FOREIGN KEY (device_id)
        REFERENCES devices(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS router_integrations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    provider VARCHAR(100) NOT NULL,
    name VARCHAR(255) NULL,

    enabled BOOLEAN NOT NULL DEFAULT FALSE,

    host VARCHAR(255) NULL,
    username VARCHAR(255) NULL,

    credential_reference VARCHAR(255) NULL,

    status ENUM('not_configured', 'connected', 'error', 'unsupported')
        NOT NULL DEFAULT 'not_configured',

    last_checked_at DATETIME NULL,

    error_message TEXT NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_router_integrations_enabled (enabled),
    INDEX idx_router_integrations_status (status)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    admin_user_id BIGINT UNSIGNED NULL,

    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100) NULL,
    target_id BIGINT UNSIGNED NULL,

    details JSON NULL,

    ip_address VARCHAR(45) NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    INDEX idx_audit_logs_admin (admin_user_id),
    INDEX idx_audit_logs_action (action),
    INDEX idx_audit_logs_target (target_type, target_id),
    INDEX idx_audit_logs_created (created_at),

    CONSTRAINT fk_audit_logs_admin
        FOREIGN KEY (admin_user_id)
        REFERENCES admin_users(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;