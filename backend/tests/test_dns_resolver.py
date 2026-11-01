"""
AegisDNS - DNS Resolution & Filtering Resolver Tests
Tests DNS resolution, latency measurement, and synthetic sinkhole response generation.
"""

import dns.message
import dns.rdatatype
from services.dns_service import DnsService
from dns_resolver.sinkhole import DnsSinkhole
from dns_resolver.resolver_server import DnsFilteringResolver


def test_dnspython_resolution(client):
    """Test actual DNS query resolution using dnspython"""
    res = DnsService.resolve_domain('one.one.one.one', query_type='A')
    assert res['domain'] == 'one.one.one.one'
    assert res['queryType'] == 'A'
    assert 'status' in res
    assert 'responseTimeMs' in res
    assert isinstance(res['responseTimeMs'], (int, float))


def test_dns_sinkhole_packet_generation():
    """Test synthetic 0.0.0.0 sinkhole response creation for blocked domains"""
    query = dns.message.make_query('malicious-c2-host.xyz', dns.rdatatype.A)
    response = DnsSinkhole.create_blocked_response(query, sinkhole_ip="0.0.0.0")

    assert response.id == query.id
    assert len(response.answer) == 1
    assert response.answer[0][0].to_text() == '0.0.0.0'


def test_dns_filtering_resolver_block_decision(client, app):
    """Test DNS filtering resolver blocklist cache evaluation"""
    resolver = DnsFilteringResolver(app=app)
    # Seeded malicious domain must be flagged
    assert resolver.is_domain_blocked('paypa1-security-update-verify.com') is True
    assert resolver.is_domain_blocked('subdomain.c2-trojan-controller-sync.net') is True
    # Clean domain must not be blocked
    assert resolver.is_domain_blocked('google.com') is False
