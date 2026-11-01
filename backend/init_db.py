"""
AegisDNS - Database Initialization & Seeding Script
Executes table creation, creates indexes, and inserts baseline security data.

Usage:
    python init_db.py
"""

import sys
import logging
from app import create_app, seed_initial_data
from extensions import db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("InitDB")


def initialize_database():
    logger.info("Initializing AegisDNS Database...")
    app = create_app('development')

    with app.app_context():
        try:
            logger.info(f"Target Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
            db.create_all()
            logger.info("Database tables and indexes created successfully.")
            seed_initial_data(app)
            logger.info("Initial data successfully seeded!")
            print("===================================================================")
            print(" AegisDNS Database Setup Complete!")
            print(" Default Administrator: admin_secops / CyberShield#2026!")
            print("===================================================================")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            sys.exit(1)


if __name__ == '__main__':
    initialize_database()

