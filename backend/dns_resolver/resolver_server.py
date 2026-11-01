"""
AegisDNS - DNS Filtering Resolver Daemon
Intercepts incoming DNS queries on UDP port 53 / 5353, evaluates blocklists,
returns sinkhole responses for malicious domains, and forwards clean queries upstream.
"""

import socket
import threading
import logging
import time
import dns.message
import dns.query
import dns.rdatatype
from config import Config
from dns_resolver.sinkhole import DnsSinkhole
from utils.domain_utils import normalize_domain

logger = logging.getLogger("AegisDnsResolver")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class DnsFilteringResolver:
    def __init__(self, host: str = None, port: int = None, upstream_server: str = None, upstream_port: int = None,
                 sinkhole_ip: str = None, block_response_type: str = None, app=None):
        self.host = host or Config.DNS_LISTEN_HOST
        self.port = port if port is not None else Config.DNS_LISTEN_PORT
        self.upstream_server = upstream_server or Config.UPSTREAM_DNS_SERVER
        self.upstream_port = upstream_port if upstream_port is not None else Config.UPSTREAM_DNS_PORT
        self.sinkhole_ip = sinkhole_ip or Config.SINKHOLE_IP
        self.block_response_type = block_response_type or Config.BLOCK_RESPONSE_TYPE
        self.app = app # Flask application reference for database context

        self._socket = None
        self._running = False
        self._thread = None

        # Fast in-memory blocklist set for microsecond lookup performance
        self._memory_blocklist = set()
        self._refresh_blocklist_cache()

    def _refresh_blocklist_cache(self):
        """Refreshes in-memory blocklist from database if available"""
        try:
            if self.app:
                with self.app.app_context():
                    from models.domain import BlockedDomain
                    domains = BlockedDomain.query.all()
                    self._memory_blocklist = {d.domain.lower() for d in domains}
            else:
                # Default baseline rules
                self._memory_blocklist = {
                    'paypa1-security-update-verify.com',
                    'c2-trojan-controller-sync.net',
                    'malware-payload-stage1.biz',
                    'miningpool-xmrig-eu.stream',
                    'apple-id-suspended-login.cc',
                    'stealth-keylogger-drop.online'
                }
            logger.info(f"Loaded {len(self._memory_blocklist)} domains into fast DNS sinkhole cache.")
        except Exception as e:
            logger.warning(f"Could not load blocklist from DB; using memory cache: {e}")

    def is_domain_blocked(self, domain: str) -> bool:
        """
        Evaluates whether domain is currently blocked.
        """
        clean_domain = normalize_domain(domain)
        if clean_domain in self._memory_blocklist:
            return True

        # Check subdomains (e.g. sub.evil.com when evil.com is blocked)
        parts = clean_domain.split('.')
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in self._memory_blocklist:
                return True

        # Also query database dynamically if app context available
        if self.app:
            try:
                with self.app.app_context():
                    from models.domain import BlockedDomain
                    from models.setting import SystemSetting

                    # Check master protection toggle
                    protection_enabled = SystemSetting.get_val('protection_enabled', True)
                    if not protection_enabled:
                        return False

                    match = BlockedDomain.query.filter_by(domain=clean_domain).first()
                    if match:
                        self._memory_blocklist.add(clean_domain)
                        return True
            except Exception:
                pass

        return False

    def handle_query(self, data: bytes, client_addr: tuple):
        """
        Processes a single inbound UDP DNS query packet.
        """
        start_time = time.perf_counter()
        try:
            query = dns.message.from_wire(data)
        except Exception as e:
            logger.warning(f"Malformed DNS wire packet from {client_addr}: {e}")
            return

        if not query.question:
            return

        q = query.question[0]
        domain_name = q.name.to_text().rstrip('.')
        qtype_str = dns.rdatatype.to_text(q.rdtype)
        client_ip = client_addr[0]

        is_blocked = self.is_domain_blocked(domain_name)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if is_blocked:
            # Domain is blocked - construct sinkhole response
            logger.warning(f"[SINKHOLE INTERCEPTED] {client_ip} queried BLOCKED domain '{domain_name}' ({qtype_str}) -> Sinkhole 0.0.0.0")
            response = DnsSinkhole.create_blocked_response(
                query_message=query,
                sinkhole_ip=self.sinkhole_ip,
                response_type=self.block_response_type
            )
            response_data = response.to_wire()
            self._socket.sendto(response_data, client_addr)

            # Record in DnsLog database table
            if self.app:
                try:
                    with self.app.app_context():
                        from services.dns_service import DnsService
                        from services.failover_service import FailoverService
                        DnsService.log_query(
                            domain=domain_name,
                            client_ip=client_ip,
                            query_type=qtype_str,
                            response_time_ms=elapsed_ms,
                            status='BLOCKED',
                            resolved_ip=self.sinkhole_ip,
                            category='Sinkhole Null-Route',
                            is_sinkholed=True
                        )
                        FailoverService.record_query_served(is_blocked=True)
                except Exception as e:
                    logger.debug(f"Failed to record sinkhole log: {e}")

        else:
            # Domain is clean - forward to upstream resolver
            # Retrieve currently active healthy upstream from FailoverService
            active_upstream = self.upstream_server
            active_port = self.upstream_port
            if self.app:
                try:
                    from services.failover_service import FailoverService
                    active_upstream, active_port, _ = FailoverService.get_active_upstream()
                except Exception:
                    pass

            try:
                upstream_response = dns.query.udp(
                    q=query,
                    where=active_upstream,
                    port=active_port,
                    timeout=2.5
                )
                self._socket.sendto(upstream_response.to_wire(), client_addr)
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                logger.debug(f"[RESOLVED CLEAN] {domain_name} ({qtype_str}) forwarded to {active_upstream} in {elapsed_ms:.1f}ms")

                # Extract first resolved IP for logging
                resolved_ip = None
                for rrset in upstream_response.answer:
                    if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        resolved_ip = rrset[0].to_text()
                        break

                if self.app:
                    try:
                        with self.app.app_context():
                            from services.dns_service import DnsService
                            from services.failover_service import FailoverService
                            DnsService.log_query(
                                domain=domain_name,
                                client_ip=client_ip,
                                query_type=qtype_str,
                                response_time_ms=elapsed_ms,
                                status='ALLOWED',
                                resolved_ip=resolved_ip or 'Resolved',
                                category='Forwarded Resolution',
                                is_sinkholed=False
                            )
                            FailoverService.record_query_served(is_blocked=False)
                    except Exception as e:
                        logger.debug(f"Failed to record allowed log: {e}")

            except Exception as e:
                logger.warning(f"Upstream forwarding error on {active_upstream} for {domain_name}: {e}. Evaluating failover...")
                recovered = False
                if self.app:
                    try:
                        with self.app.app_context():
                            from services.failover_service import FailoverService
                            failover_res = FailoverService.execute_failover(
                                trigger_reason=f"IN_FLIGHT_UPSTREAM_ERROR_{type(e).__name__}"
                            )
                            if failover_res.get('success'):
                                new_upstream, new_port, _ = FailoverService.get_active_upstream()
                                backup_response = dns.query.udp(
                                    q=query,
                                    where=new_upstream,
                                    port=new_port,
                                    timeout=2.5
                                )
                                self._socket.sendto(backup_response.to_wire(), client_addr)
                                recovered = True
                                FailoverService.record_query_served(is_blocked=False)
                                logger.info(f"[FAILOVER RECOVERED] {domain_name} answered by backup {new_upstream}")
                    except Exception as failover_err:
                        logger.error(f"In-flight failover retry failed: {failover_err}")

                if not recovered:
                    error_resp = dns.message.make_response(query)
                    error_resp.set_rcode(dns.rcode.SERVFAIL)
                    self._socket.sendto(error_resp.to_wire(), client_addr)

    def _listen_loop(self):
        """Main UDP server loop"""
        logger.info(f"AegisDNS Filtering Resolver listening on UDP {self.host}:{self.port}")
        logger.info(f"Upstream DNS: {self.upstream_server}:{self.upstream_port} | Sinkhole IP: {self.sinkhole_ip}")

        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                # Spawn worker thread for non-blocking DNS query handling
                threading.Thread(target=self.handle_query, args=(data, addr), daemon=True).start()
            except (socket.error, OSError):
                if not self._running:
                    break

    def start(self, run_in_background: bool = True):
        """Starts the DNS resolver daemon"""
        if self._running:
            return

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._socket.bind((self.host, self.port))
        except OSError as e:
            logger.error(f"Failed to bind DNS socket on {self.host}:{self.port} (Port may require admin privileges or is in use): {e}")
            return

        self._running = True
        self._refresh_blocklist_cache()

        if run_in_background:
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
        else:
            self._listen_loop()

    def stop(self):
        """Gracefully terminates the DNS resolver"""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        logger.info("AegisDNS Filtering Resolver stopped.")


if __name__ == "__main__":
    print("===================================================================")
    print(" AegisDNS Filtering Resolver Standalone Prototype")
    print(f" Listening: 127.0.0.1:5353 (UDP)")
    print(" Test Command: nslookup -port=5353 paypa1-security-update-verify.com 127.0.0.1")
    print(" Expected Output: 0.0.0.0 (Sinkholed)")
    print("===================================================================")
    resolver = DnsFilteringResolver()
    try:
        resolver.start(run_in_background=False)
    except KeyboardInterrupt:
        resolver.stop()

