"""
AegisDNS - DNS Resolver Package
"""

from dns_resolver.sinkhole import DnsSinkhole
from dns_resolver.resolver_server import DnsFilteringResolver

__all__ = ['DnsSinkhole', 'DnsFilteringResolver']

