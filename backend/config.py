"""
AegisDNS - Application Configuration Module
Handles configuration for Flask, MySQL Database, JWT, DNS, and Security Settings.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config:
    """Base Configuration with Secure Defaults"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'aegis_super_secret_cyber_key_change_in_production_2026!')
    
    # Database Settings (MySQL Default)
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')
    DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_NAME = os.getenv('DB_NAME', 'aegis_dns_db')
    
    MYSQL_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    SQLITE_DATABASE_URI = f"sqlite:///{os.path.join(basedir, 'aegis_dns.db')}"
    
    # Primary Database URI
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', MYSQL_DATABASE_URI)
    FALLBACK_TO_SQLITE = os.getenv('FALLBACK_TO_SQLITE', 'true').lower() in ('true', '1', 't')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 280,
        'pool_pre_ping': True
    }
    
    # JWT Settings
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'aegis_jwt_cyber_token_secret_key_984321_secure!')
    jwt_minutes = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES_MINUTES', '1440'))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=jwt_minutes)
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    
    # DNS Resolver Settings
    DNS_LISTEN_HOST = os.getenv('DNS_LISTEN_HOST', '127.0.0.1')
    DNS_LISTEN_PORT = int(os.getenv('DNS_LISTEN_PORT', '5354')) # Port 5354 for safe localhost testing without admin socket collision
    UPSTREAM_DNS_SERVER = os.getenv('UPSTREAM_DNS_SERVER', '1.1.1.1')
    UPSTREAM_DNS_PORT = int(os.getenv('UPSTREAM_DNS_PORT', '53'))
    SINKHOLE_IP = os.getenv('SINKHOLE_IP', '0.0.0.0')
    BLOCK_RESPONSE_TYPE = os.getenv('BLOCK_RESPONSE_TYPE', 'SINKHOLE_IP')
    
    # Threat Intelligence API Keys
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    ALIENVAULT_OTX_API_KEY = os.getenv('ALIENVAULT_OTX_API_KEY', '')
    
    # CORS Origins
    CORS_ORIGINS = ['*', 'http://localhost:5000', 'http://127.0.0.1:5000', 'http://localhost:8080', 'http://127.0.0.1:8080']
    
    # Seed Administrator
    ADMIN_FULL_NAME = os.getenv('ADMIN_FULL_NAME', 'SecOps Administrator')
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin_secops')
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@aegisdns.security')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'CyberShield#2026!')


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    DEBUG = False
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    FALLBACK_TO_SQLITE = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=10)


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    FALLBACK_TO_SQLITE = False


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

