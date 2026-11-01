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

-- 10. Virtual Policies Table (Digital Twin Configuration Studio)
CREATE TABLE IF NOT EXISTS `virtual_policies` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(150) NOT NULL UNIQUE,
    `description` TEXT NULL,
    `entropy_threshold` FLOAT NOT NULL DEFAULT 3.90,
    `blocked_tlds_json` TEXT NULL,
    `blocked_categories_json` TEXT NULL,
    `dga_protection_mode` VARCHAR(50) NOT NULL DEFAULT 'Balanced',
    `ai_heuristic_weight` FLOAT NOT NULL DEFAULT 1.0,
    `min_confidence_score` INT NOT NULL DEFAULT 80,
    `action_malicious` VARCHAR(50) NOT NULL DEFAULT 'SINKHOLE_0_0_0_0',
    `action_suspicious` VARCHAR(50) NOT NULL DEFAULT 'CHALLENGE_FLAG',
    `custom_whitelist_json` TEXT NULL,
    `custom_blacklist_json` TEXT NULL,
    `is_baseline` BOOLEAN NOT NULL DEFAULT FALSE,
    `created_by` VARCHAR(100) NOT NULL DEFAULT 'SecOps Administrator',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_policy_name` (`name`),
    INDEX `idx_policy_baseline` (`is_baseline`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 11. Simulation Scenarios Table (Attack & Traffic Datasets with Ground Truth)
CREATE TABLE IF NOT EXISTS `simulation_scenarios` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scenario_key` VARCHAR(80) NOT NULL UNIQUE,
    `name` VARCHAR(150) NOT NULL,
    `category` VARCHAR(100) NOT NULL,
    `description` TEXT NOT NULL,
    `difficulty` VARCHAR(30) NOT NULL DEFAULT 'Advanced',
    `domain_count` INT NOT NULL DEFAULT 0,
    `dataset_json` LONGTEXT NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_scenario_key` (`scenario_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 12. Simulation Runs Table (Aggregated Digital Twin Run Metrics)
CREATE TABLE IF NOT EXISTS `simulation_runs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `run_uuid` VARCHAR(64) NOT NULL UNIQUE,
    `policy_id` INT NULL,
    `policy_name` VARCHAR(150) NOT NULL,
    `scenario_id` INT NULL,
    `scenario_name` VARCHAR(150) NOT NULL,
    `total_queries` INT NOT NULL DEFAULT 0,
    `true_positives` INT NOT NULL DEFAULT 0,
    `false_positives` INT NOT NULL DEFAULT 0,
    `true_negatives` INT NOT NULL DEFAULT 0,
    `false_negatives` INT NOT NULL DEFAULT 0,
    `accuracy` FLOAT NOT NULL DEFAULT 0.0,
    `precision` FLOAT NOT NULL DEFAULT 0.0,
    `recall` FLOAT NOT NULL DEFAULT 0.0,
    `f1_score` FLOAT NOT NULL DEFAULT 0.0,
    `fpr` FLOAT NOT NULL DEFAULT 0.0,
    `fnr` FLOAT NOT NULL DEFAULT 0.0,
    `effectiveness_score` FLOAT NOT NULL DEFAULT 0.0,
    `execution_time_ms` FLOAT NOT NULL DEFAULT 0.0,
    `recommendations_json` TEXT NULL,
    `user_id` INT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`policy_id`) REFERENCES `virtual_policies`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`scenario_id`) REFERENCES `simulation_scenarios`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_sim_run_uuid` (`run_uuid`),
    INDEX `idx_sim_run_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 13. Simulation Items Table (Per-Domain Forensic Telemetry)
CREATE TABLE IF NOT EXISTS `simulation_items` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `run_id` INT NOT NULL,
    `domain` VARCHAR(255) NOT NULL,
    `ground_truth` VARCHAR(30) NOT NULL,
    `simulated_action` VARCHAR(30) NOT NULL,
    `simulated_verdict` VARCHAR(30) NOT NULL,
    `category` VARCHAR(100) NULL,
    `classification_type` VARCHAR(10) NOT NULL, -- TP, FP, TN, FN
    `is_correct` BOOLEAN NOT NULL,
    `confidence_score` INT NOT NULL DEFAULT 0,
    `entropy_score` FLOAT NULL,
    `trigger_rules_json` TEXT NULL,
    `forensic_reason` TEXT NULL,
    `latency_ms` FLOAT NOT NULL DEFAULT 1.0,
    FOREIGN KEY (`run_id`) REFERENCES `simulation_runs`(`id`) ON DELETE CASCADE,
    INDEX `idx_sim_item_run` (`run_id`),
    INDEX `idx_sim_item_type` (`classification_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

