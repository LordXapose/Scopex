"""
SCOPEX scope repository.

Provides persistence operations for authorized scope targets.

The repository is responsible only for database access.
Authorization and target normalization remain in ScopeManager.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopex.database.models import ScopeTarget


class ScopeRepository:
    """Database repository for authorized scope targets."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        target_type: str,
        value: str,
    ) -> ScopeTarget:
        """Create a new authorized scope target."""

        target = ScopeTarget(
            target_type=target_type,
            value=value,
        )

        self.session.add(target)
        self.session.flush()

        return target

    def get_by_id(
        self,
        target_id: int,
    ) -> ScopeTarget | None:
        """Return a scope target by database ID."""

        return self.session.get(
            ScopeTarget,
            target_id,
        )

    def get_by_type_and_value(
        self,
        target_type: str,
        value: str,
    ) -> ScopeTarget | None:
        """Return a scope target by type and normalized value."""

        statement = select(ScopeTarget).where(
            ScopeTarget.target_type == target_type,
            ScopeTarget.value == value,
        )

        return self.session.scalar(statement)

    def get_all(
        self,
        enabled_only: bool = True,
    ) -> list[ScopeTarget]:
        """Return persisted scope targets."""

        statement = select(ScopeTarget).order_by(
            ScopeTarget.target_type,
            ScopeTarget.value,
        )

        if enabled_only:
            statement = statement.where(
                ScopeTarget.enabled.is_(True)
            )

        return list(
            self.session.scalars(statement).all()
        )

    def delete(
        self,
        target_id: int,
    ) -> bool:
        """Permanently delete a scope target."""

        target = self.get_by_id(target_id)

        if target is None:
            return False

        self.session.delete(target)
        self.session.flush()

        return True

    def set_enabled(
        self,
        target_id: int,
        enabled: bool,
    ) -> ScopeTarget | None:
        """Enable or disable a scope target."""

        target = self.get_by_id(target_id)

        if target is None:
            return None

        target.enabled = enabled
        self.session.flush()

        return target