"""
AegisDNS - System Settings Model
Persists runtime network protection toggles, DNS resolvers, and alert parameters in MySQL.
"""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class SystemSetting(db.Model):
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    setting_value = db.Column(db.Text, nullable=False)
    value_type = db.Column(db.String(30), nullable=False, default='string') # string, boolean, integer, json
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    @classmethod
    def get_val(cls, key: str, default=None):
        """Retrieves and parses a typed setting value"""
        try:
            row = cls.query.filter_by(setting_key=key).first()
            if not row:
                return default
            val = row.setting_value
            if row.value_type == 'boolean':
                return str(val).lower() in ('true', '1', 't', 'yes')
            elif row.value_type == 'integer':
                try:
                    return int(val)
                except ValueError:
                    return default
            return val
        except Exception:
            return default

    @classmethod
    def set_val(cls, key: str, value, value_type: str = 'string', description: str = None):
        """Sets or updates a setting value"""
        row = cls.query.filter_by(setting_key=key).first()
        str_val = str(value)
        if isinstance(value, bool):
            value_type = 'boolean'
            str_val = 'true' if value else 'false'
        elif isinstance(value, int):
            value_type = 'integer'

        if row:
            row.setting_value = str_val
            row.value_type = value_type
            if description:
                row.description = description
            row.updated_at = utc_now()
        else:
            row = cls(
                setting_key=key,
                setting_value=str_val,
                value_type=value_type,
                description=description
            )
            db.session.add(row)
        return row

    def to_dict(self):
        return {
            'key': self.setting_key,
            'value': self.get_val(self.setting_key),
            'type': self.value_type,
            'description': self.description,
            'updatedAt': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }

