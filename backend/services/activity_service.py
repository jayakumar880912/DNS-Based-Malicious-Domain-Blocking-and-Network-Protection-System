"""
AegisDNS - Activity Service
Central service for recording immutable audit logs and querying system activity.
"""

import uuid
from datetime import datetime, timezone
from flask import request
from extensions import db
from models.activity import ActivityLog
from utils.security import get_current_user_obj


class ActivityService:
    @staticmethod
    def log(activity_type: str, target: str, status: str = 'INFO', details: str = '', actor: str = None, ip_origin: str = None) -> ActivityLog:
        """
        Records an audit activity event into the database.
        """
        try:
            # Determine actor if not provided
            if not actor:
                current_user = get_current_user_obj()
                actor = current_user.full_name if current_user else 'SecOps Administrator'

            # Determine client IP if not provided
            if not ip_origin:
                if request:
                    ip_origin = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()
                else:
                    ip_origin = '127.0.0.1'

            # Generate unique activity ID: ACT-XXXX
            short_id = uuid.uuid4().hex[:6].upper()
            act_id = f"ACT-{short_id}"

            entry = ActivityLog(
                activity_id=act_id,
                activity_type=activity_type,
                actor=actor,
                target=target,
                ip_origin=ip_origin,
                status=status.upper(),
                details=details,
                created_at=datetime.now(timezone.utc)
            )

            db.session.add(entry)
            db.session.commit()
            return entry
        except Exception as e:
            db.session.rollback()
            # Do not allow logging failures to break parent workflow
            print(f"[ActivityLog Error] Failed to write log: {e}")
            return None

    @staticmethod
    def get_logs(page: int = 1, per_page: int = 50, activity_type: str = None, status: str = None, search: str = None, start_date: str = None, end_date: str = None):
        """
        Retrieves paginated and filtered activity logs.
        """
        query = ActivityLog.query

        if activity_type and activity_type.upper() != 'ALL':
            query = query.filter(ActivityLog.activity_type.ilike(f"%{activity_type}%"))

        if status and status.upper() != 'ALL':
            query = query.filter(ActivityLog.status == status.upper())

        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                (ActivityLog.target.ilike(search_term)) |
                (ActivityLog.actor.ilike(search_term)) |
                (ActivityLog.details.ilike(search_term)) |
                (ActivityLog.activity_id.ilike(search_term)) |
                (ActivityLog.ip_origin.ilike(search_term))
            )

        if start_date:
            try:
                dt_start = datetime.strptime(start_date, '%Y-%m-%d')
                query = query.filter(ActivityLog.created_at >= dt_start)
            except ValueError:
                pass

        if end_date:
            try:
                dt_end = datetime.strptime(end_date + ' 23:59:59', '%Y-%m-%d %H:%M:%S')
                query = query.filter(ActivityLog.created_at <= dt_end)
            except ValueError:
                pass

        query = query.order_by(ActivityLog.created_at.desc())
        paginated = query.paginate(page=page, per_page=per_page, error_out=False)

        return {
            'total': paginated.total,
            'pages': paginated.pages,
            'currentPage': paginated.page,
            'perPage': paginated.per_page,
            'logs': [item.to_dict() for item in paginated.items]
        }

