"""
SCOPEX DNS intelligence package.

Provides DNS resolution and subdomain discovery functionality
for authorized attack-surface reconnaissance.
"""

from scopex.dns.discovery import (
    SubdomainCandidate,
    SubdomainDiscovery,
)
from scopex.dns.resolver import DNSResolver, DNSResult

__all__ = [
    "DNSResolver",
    "DNSResult",
    "SubdomainCandidate",
    "SubdomainDiscovery",
]