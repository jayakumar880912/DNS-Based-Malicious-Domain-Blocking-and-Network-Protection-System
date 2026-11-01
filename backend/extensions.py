"""
AegisDNS - Flask Extensions Module
Initializes SQLAlchemy, Flask-JWT-Extended, and CORS extensions.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS

db = SQLAlchemy()
jwt = JWTManager()
cors = CORS()

# In-memory revoked JWT tokens set for token invalidation / logout
jwt_blocklist = set()


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload.get('jti')
    return jti in jwt_blocklist

