"""
SCOPEX DNS intelligence package.

Provides DNS resolution and discovery functionality for
authorized attack-surface reconnaissance.
"""

from scopex.dns.resolver import DNSResolver, DNSResult

__all__ = [
    "DNSResolver",
    "DNSResult",
]
