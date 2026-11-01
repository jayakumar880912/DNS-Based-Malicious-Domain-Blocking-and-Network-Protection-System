"""
AegisDNS - DNS Resolution & Monitoring Service
Executes actual network DNS queries using dnspython, measures latency, and logs queries.
"""

import time
import uuid
from datetime import datetime, timezone
import dns.resolver
import dns.exception
from extensions import db
from models.dns_log import DnsLog
from models.setting import SystemSetting


class DnsService:
    @staticmethod
    def resolve_domain(domain: str, query_type: str = 'A', upstream: str = None, timeout: float = 3.0) -> dict:
        """
        Performs actual DNS resolution using dnspython against upstream resolver.
        Measures latency in milliseconds and extracts resolved IPs/records.
        """
        if not upstream:
            try:
                from services.failover_service import FailoverService
                active_up, _, _ = FailoverService.get_active_upstream()
                upstream = active_up
            except Exception:
                try:
                    upstream = SystemSetting.get_val('upstream_dns', '1.1.1.1')
                    upstream = upstream.split()[0].strip() if upstream else '1.1.1.1'
                except Exception:
                    upstream = '1.1.1.1'

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [upstream]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        start_time = time.perf_counter()
        records = []
        status = 'ALLOWED'
        error_msg = None

        try:
            answer = resolver.resolve(domain, query_type)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            for rdata in answer:
                records.append(rdata.to_text())

            resolved_ip = records[0] if records and query_type in ('A', 'AAAA') else (records[0] if records else None)

            return {
                'success': True,
                'domain': domain,
                'queryType': query_type,
                'records': records,
                'resolvedIp': resolved_ip,
                'responseTimeMs': round(elapsed_ms, 2),
                'status': 'RESOLVED',
                'upstream': upstream,
                'error': None
            }

        except dns.resolver.NXDOMAIN:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                'success': False,
                'domain': domain,
                'queryType': query_type,
                'records': [],
                'resolvedIp': None,
                'responseTimeMs': round(elapsed_ms, 2),
                'status': 'NXDOMAIN',
                'upstream': upstream,
                'error': 'Domain name does not exist (NXDOMAIN).'
            }

        except dns.resolver.NoAnswer:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                'success': False,
                'domain': domain,
                'queryType': query_type,
                'records': [],
                'resolvedIp': None,
                'responseTimeMs': round(elapsed_ms, 2),
                'status': 'NO_ANSWER',
                'upstream': upstream,
                'error': f'No {query_type} records found for domain.'
            }

        except dns.resolver.Timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                'success': False,
                'domain': domain,
                'queryType': query_type,
                'records': [],
                'resolvedIp': None,
                'responseTimeMs': round(elapsed_ms, 2),
                'status': 'TIMEOUT',
                'upstream': upstream,
                'error': f'Upstream resolver {upstream} timed out after {timeout}s.'
            }

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                'success': False,
                'domain': domain,
                'queryType': query_type,
                'records': [],
                'resolvedIp': None,
                'responseTimeMs': round(elapsed_ms, 2),
                'status': 'RESOLUTION_FAILED',
                'upstream': upstream,
                'error': str(e)
            }

    @staticmethod
    def log_query(domain: str, client_ip: str, query_type: str, response_time_ms: float,
                  status: str, resolved_ip: str = None, category: str = None, is_sinkholed: bool = False) -> DnsLog:
        """
        Saves a DNS lookup event into the dns_logs database table.
        """
        try:
            log_uuid = f"DNS-{uuid.uuid4().hex[:4].upper()}"
            entry = DnsLog(
                log_uuid=log_uuid,
                domain=domain,
                client_ip=client_ip,
                query_type=query_type,
                resolved_ip=resolved_ip,
                response_time_ms=response_time_ms,
                status=status.upper(),
                category=category or ('Sinkhole Null-Route' if is_sinkholed else 'General DNS'),
                is_sinkholed=is_sinkholed,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(entry)
            db.session.commit()
            return entry
        except Exception as e:
            db.session.rollback()
            print(f"[DnsService Error] Failed to log DNS query: {e}")
            return None

    @staticmethod
    def get_logs(page: int = 1, per_page: int = 50, status: str = None, query_type: str = None, search: str = None, sort_by: str = 'time_desc'):
        """
        Queries DNS monitoring logs with filtering and sorting.
        """
        query = DnsLog.query

        if status and status.upper() != 'ALL':
            query = query.filter(DnsLog.status == status.upper())

        if query_type and query_type.upper() != 'ALL':
            query = query.filter(DnsLog.query_type == query_type.upper())

        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                (DnsLog.domain.ilike(search_term)) |
                (DnsLog.client_ip.ilike(search_term)) |
                (DnsLog.log_uuid.ilike(search_term))
            )

        if sort_by == 'time_asc':
            query = query.order_by(DnsLog.created_at.asc())
        elif sort_by == 'latency_desc':
            query = query.order_by(DnsLog.response_time_ms.desc())
        elif sort_by == 'latency_asc':
            query = query.order_by(DnsLog.response_time_ms.asc())
        elif sort_by == 'domain_asc':
            query = query.order_by(DnsLog.domain.asc())
        else: # default time_desc
            query = query.order_by(DnsLog.created_at.desc())

        paginated = query.paginate(page=page, per_page=per_page, error_out=False)

        return {
            'total': paginated.total,
            'pages': paginated.pages,
            'currentPage': paginated.page,
            'perPage': paginated.per_page,
            'logs': [item.to_dict() for item in paginated.items]
        }

