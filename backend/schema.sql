-- =============================================================================
-- AegisDNS - DNS-Based Malicious Domain Blocking and Network Protection System
-- MySQL Relational Database Schema
-- Character Set: utf8mb4 | Engine: InnoDB
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `aegis_dns_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `aegis_dns_db`;

-- 1. Users Table (Authentication & Access Control)
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `full_name` VARCHAR(120) NOT NULL,
    `username` VARCHAR(80) NOT NULL UNIQUE,
    `email` VARCHAR(120) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` VARCHAR(50) NOT NULL DEFAULT 'Cybersecurity Incident Lead',
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
    `last_login_at` DATETIME NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_users_username` (`username`),
    INDEX `idx_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Domain Checks Table (Inspection History & Reputation Results)
CREATE TABLE IF NOT EXISTS `domain_checks` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `domain` VARCHAR(255) NOT NULL,
    `status` VARCHAR(30) NOT NULL, -- 'SAFE', 'MALICIOUS', 'SUSPICIOUS'
    `category` VARCHAR(120) NULL,
    `risk_score` INT NOT NULL DEFAULT 0,
    `resolved_ip` VARCHAR(100) NULL,
    `nameserver` VARCHAR(150) NULL,
    `entropy_score` FLOAT NULL,
    `threat_sources_json` TEXT NULL,
    `verdict_reason` TEXT NULL,
    `user_id` INT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_checks_domain` (`domain`),
    INDEX `idx_checks_status` (`status`),
    INDEX `idx_checks_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Malicious Domains Table (Verified Threat Feed Signatures)
CREATE TABLE IF NOT EXISTS `malicious_domains` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `domain` VARCHAR(255) NOT NULL UNIQUE,
    `threat_category` VARCHAR(100) NOT NULL,
    `source` VARCHAR(100) NOT NULL,
    `severity` VARCHAR(30) NOT NULL DEFAULT 'High',
    `confidence_score` INT NOT NULL DEFAULT 95,
    `first_seen_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_verified_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
    INDEX `idx_malicious_domain` (`domain`),
    INDEX `idx_malicious_category` (`threat_category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Suspicious Domains Table (Lexical & Shannon Entropy Flags)
CREATE TABLE IF NOT EXISTS `suspicious_domains` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `domain` VARCHAR(255) NOT NULL UNIQUE,
    `threat_category` VARCHAR(100) NOT NULL DEFAULT 'Heuristic Anomaly',
    `entropy_score` FLOAT NULL,
    `reason` VARCHAR(255) NULL,
    `status` VARCHAR(50) NOT NULL DEFAULT 'Under Review',
    `detected_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_suspicious_domain` (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Blocked Domains Table (Active Sinkhole Policy Rules)
CREATE TABLE IF NOT EXISTS `blocked_domains` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `policy_code` VARCHAR(50) NULL UNIQUE,
    `domain` VARCHAR(255) NOT NULL UNIQUE,
    `threat_category` VARCHAR(100) NOT NULL DEFAULT 'Custom Admin Policy',
    `blocking_reason` TEXT NOT NULL,
    `blocking_status` VARCHAR(50) NOT NULL DEFAULT 'Active Blocked',
    `severity` VARCHAR(30) NOT NULL DEFAULT 'High',
    `source` VARCHAR(100) NOT NULL DEFAULT 'Manual Administrator Rule',
    `blocked_by_user_id` INT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`blocked_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_blocked_domain` (`domain`),
    INDEX `idx_blocked_category` (`threat_category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. DNS Logs Table (Real-time Resolution Telemetry)
CREATE TABLE IF NOT EXISTS `dns_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `log_uuid` VARCHAR(50) NOT NULL,
    `domain` VARCHAR(255) NOT NULL,
    `client_ip` VARCHAR(60) NOT NULL,
    `query_type` VARCHAR(20) NOT NULL DEFAULT 'A',
    `resolved_ip` VARCHAR(100) NULL,
    `response_time_ms` FLOAT NOT NULL DEFAULT 12.0,
    `status` VARCHAR(30) NOT NULL, -- 'ALLOWED', 'BLOCKED', 'SUSPICIOUS'
    `category` VARCHAR(100) NULL,
    `is_sinkholed` BOOLEAN NOT NULL DEFAULT FALSE,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_dns_uuid` (`log_uuid`),
    INDEX `idx_dns_domain` (`domain`),
    INDEX `idx_dns_client` (`client_ip`),
    INDEX `idx_dns_status` (`status`),
    INDEX `idx_dns_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. Threat Detections Table (Security Incident Records)
CREATE TABLE IF NOT EXISTS `threat_detections` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `incident_id` VARCHAR(50) NOT NULL UNIQUE,
    `domain` VARCHAR(255) NOT NULL,
    `category` VARCHAR(100) NOT NULL,
    `severity` VARCHAR(30) NOT NULL, -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    `source_feed` VARCHAR(120) NOT NULL,
    `risk_score` INT NOT NULL DEFAULT 90,
    `action_taken` VARCHAR(120) NOT NULL DEFAULT 'DNS Sinkhole (0.0.0.0)',
    `target_ip` VARCHAR(100) NULL,
    `client_origin` VARCHAR(150) NULL,
    `ioc_details` TEXT NULL,
    `detected_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_threat_id` (`incident_id`),
    INDEX `idx_threat_domain` (`domain`),
    INDEX `idx_threat_severity` (`severity`),
    INDEX `idx_threat_detected` (`detected_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 8. Activity Logs Table (System Audit Trail)
CREATE TABLE IF NOT EXISTS `activity_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `activity_id` VARCHAR(50) NOT NULL UNIQUE,
    `activity_type` VARCHAR(100) NOT NULL,
    `actor` VARCHAR(120) NOT NULL DEFAULT 'SecOps Administrator',
    `target` VARCHAR(255) NOT NULL,
    `ip_origin` VARCHAR(60) NOT NULL DEFAULT '127.0.0.1',
    `status` VARCHAR(50) NOT NULL DEFAULT 'INFO',
    `details` TEXT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_activity_id` (`activity_id`),
    INDEX `idx_activity_type` (`activity_type`),
    INDEX `idx_activity_status` (`status`),
    INDEX `idx_activity_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 9. System Settings Table (Network Protection Configuration)
CREATE TABLE IF NOT EXISTS `system_settings` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `setting_key` VARCHAR(100) NOT NULL UNIQUE,
    `setting_value` TEXT NOT NULL,
    `value_type` VARCHAR(30) NOT NULL DEFAULT 'string',
    `description` VARCHAR(255) NULL,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

