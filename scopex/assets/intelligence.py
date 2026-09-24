"""
SCOPEX asset intelligence.

Converts DNS resolution results into persistent asset records
and supporting evidence.

This layer is intentionally separate from DNS discovery and
resolution. DNS produces observations; AssetIntelligence turns
those observations into persistent SCOPEX intelligence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopex.database.models import Asset, Evidence
from scopex.dns.resolution import ResolutionResult


class AssetIntelligence:
    """
    Persist discovered assets and DNS evidence.

    AssetIntelligence does not perform network activity. It only
    converts already-collected observations into database records.
    """

    DNS_EVIDENCE_SOURCE = "dns"

    def persist_resolution(
        self,
        session: Session,
        scan_id: int,
        result: ResolutionResult,
    ) -> list[Asset]:
        """
        Persist one DNS resolution result.

        The following assets may be created:

        - one domain asset
        - one asset for every discovered IPv4 address
        - one asset for every discovered IPv6 address

        CNAME information is stored as evidence rather than as
        a separate asset.

        Existing assets for the same scan are reused, making this
        operation idempotent for asset creation.
        """

        discovered_assets: list[Asset] = []

        now = datetime.now(timezone.utc)

        domain_asset = self._get_or_create_asset(
            session=session,
            scan_id=scan_id,
            asset_type="domain",
            value=result.name,
            hostname=result.name,
            ip_address=None,
            now=now,
        )

        discovered_assets.append(domain_asset)

        for ipv4 in result.ipv4:
            asset = self._get_or_create_asset(
                session=session,
                scan_id=scan_id,
                asset_type="ipv4",
                value=ipv4,
                hostname=result.name,
                ip_address=ipv4,
                now=now,
            )

            discovered_assets.append(asset)

        for ipv6 in result.ipv6:
            asset = self._get_or_create_asset(
                session=session,
                scan_id=scan_id,
                asset_type="ipv6",
                value=ipv6,
                hostname=result.name,
                ip_address=ipv6,
                now=now,
            )

            discovered_assets.append(asset)

        self._persist_dns_evidence(
            session=session,
            scan_id=scan_id,
            asset=domain_asset,
            result=result,
            now=now,
        )

        return discovered_assets

    def persist_resolutions(
        self,
        session: Session,
        scan_id: int,
        results: Iterable[ResolutionResult],
    ) -> list[Asset]:
        """
        Persist multiple DNS resolution results.
        """

        assets: list[Asset] = []

        for result in results:
            assets.extend(
                self.persist_resolution(
                    session=session,
                    scan_id=scan_id,
                    result=result,
                )
            )

        return assets

    @staticmethod
    def _get_or_create_asset(
        session: Session,
        scan_id: int,
        asset_type: str,
        value: str,
        hostname: str | None,
        ip_address: str | None,
        now: datetime,
    ) -> Asset:
        """
        Return an existing scan asset or create a new one.
        """

        statement = select(Asset).where(
            Asset.scan_id == scan_id,
            Asset.asset_type == asset_type,
            Asset.value == value,
        )

        asset = session.scalar(statement)

        if asset is not None:
            asset.last_seen = now
            asset.status = "active"

            if hostname is not None:
                asset.hostname = hostname

            if ip_address is not None:
                asset.ip_address = ip_address

            return asset

        asset = Asset(
            scan_id=scan_id,
            asset_type=asset_type,
            value=value,
            hostname=hostname,
            ip_address=ip_address,
            status="active",
            first_seen=now,
            last_seen=now,
        )

        session.add(asset)
        session.flush()

        return asset

    @staticmethod
    def _persist_dns_evidence(
        session: Session,
        scan_id: int,
        asset: Asset,
        result: ResolutionResult,
        now: datetime,
    ) -> Evidence:
        """
        Persist the complete DNS observation as evidence.

        Evidence is stored as JSON so the original structured
        resolution result can be reconstructed later.
        """

        evidence_data = {
            "name": result.name,
            "root_domain": result.root_domain,
            "source": result.source,
            "ipv4": list(result.ipv4),
            "ipv6": list(result.ipv6),
            "cnames": list(result.cnames),
            "status": result.status.value,
            "errors": list(result.errors),
        }

        evidence = Evidence(
            scan_id=scan_id,
            asset_id=asset.id,
            source=AssetIntelligence.DNS_EVIDENCE_SOURCE,
            evidence_type="dns_resolution",
            data=json.dumps(
                evidence_data,
                sort_keys=True,
            ),
            confidence=AssetIntelligence._calculate_confidence(
                result
            ),
            collected_at=now,
        )

        session.add(evidence)

        return evidence

    @staticmethod
    def _calculate_confidence(
        result: ResolutionResult,
    ) -> int:
        """
        Calculate a simple deterministic confidence value.

        This is intentionally conservative. It is not a
        vulnerability score.

        100:
            Successful resolution without errors.

        75:
            Partial resolution with useful DNS data.

        25:
            Unresolved candidate.

        0:
            Resolution engine error.
        """

        status = result.status.value

        if status == "resolved":
            return 100

        if status == "partial":
            return 75

        if status == "unresolved":
            return 25

        if status == "error":
            return 0

        return 0