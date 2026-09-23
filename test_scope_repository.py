"""
SCOPEX scope repository integration tests.
"""

from scopex.database.database import (
    init_database,
    session_scope,
)

from scopex.database.scope_repository import (
    ScopeRepository,
)


def test_scope_target_create_and_retrieve():
    """Test creating and retrieving a scope target."""

    init_database()

    test_domain = (
        "pytest-scope-repository.local"
    )

    with session_scope() as session:

        repository = ScopeRepository(
            session
        )

        existing = (
            repository.get_by_type_and_value(
                "domain",
                test_domain,
            )
        )

        if existing is not None:
            repository.delete(
                existing.id
            )

        target = repository.create(
            target_type="domain",
            value=test_domain,
        )

        assert target.id is not None
        assert target.target_type == "domain"
        assert target.value == test_domain
        assert target.enabled is True

        found = (
            repository.get_by_type_and_value(
                "domain",
                test_domain,
            )
        )

        assert found is not None
        assert found.id == target.id
        assert found.value == test_domain


def test_scope_target_enable_disable():
    """Test enabling and disabling a scope target."""

    init_database()

    test_domain = (
        "pytest-enable-disable.local"
    )

    with session_scope() as session:

        repository = ScopeRepository(
            session
        )

        existing = (
            repository.get_by_type_and_value(
                "domain",
                test_domain,
            )
        )

        if existing is not None:
            repository.delete(
                existing.id
            )

        target = repository.create(
            target_type="domain",
            value=test_domain,
        )

        assert target.enabled is True

        disabled = repository.set_enabled(
            target.id,
            False,
        )

        assert disabled is not None
        assert disabled.enabled is False

        enabled = repository.set_enabled(
            target.id,
            True,
        )

        assert enabled is not None
        assert enabled.enabled is True


def test_scope_target_get_all():
    """Test retrieving authorized scope targets."""

    init_database()

    test_domain = (
        "pytest-get-all.local"
    )

    with session_scope() as session:

        repository = ScopeRepository(
            session
        )

        existing = (
            repository.get_by_type_and_value(
                "domain",
                test_domain,
            )
        )

        if existing is not None:
            repository.delete(
                existing.id
            )

        target = repository.create(
            target_type="domain",
            value=test_domain,
        )

        enabled_targets = (
            repository.get_all(
                enabled_only=True
            )
        )

        assert any(
            item.id == target.id
            for item in enabled_targets
        )

        repository.set_enabled(
            target.id,
            False,
        )

        enabled_targets = (
            repository.get_all(
                enabled_only=True
            )
        )

        assert not any(
            item.id == target.id
            for item in enabled_targets
        )

        all_targets = (
            repository.get_all(
                enabled_only=False
            )
        )

        disabled_target = next(
            (
                item
                for item in all_targets
                if item.id == target.id
            ),
            None,
        )

        assert disabled_target is not None
        assert disabled_target.enabled is False


def test_scope_target_delete():
    """Test permanently deleting a scope target."""

    init_database()

    test_domain = (
        "pytest-delete.local"
    )

    with session_scope() as session:

        repository = ScopeRepository(
            session
        )

        existing = (
            repository.get_by_type_and_value(
                "domain",
                test_domain,
            )
        )

        if existing is not None:
            repository.delete(
                existing.id
            )

        target = repository.create(
            target_type="domain",
            value=test_domain,
        )

        target_id = target.id

        assert (
            repository.get_by_id(
                target_id
            )
            is not None
        )

        deleted = repository.delete(
            target_id
        )

        assert deleted is True

        assert (
            repository.get_by_id(
                target_id
            )
            is None
        )