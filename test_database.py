"""
SCOPEX database integration test.
"""

from scopex.database.database import (
    check_database_connection,
    init_database,
    session_scope,
)

from scopex.database.models import (
    Asset,
    Scan,
)


def main() -> None:
    print("=" * 60)
    print("SCOPEX DATABASE TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # Test connection
    # --------------------------------------------------------

    print("\n[1] Checking database connection...")

    if not check_database_connection():
        print("[FAIL] Database connection failed.")
        return

    print("[OK] Database connection works.")

    # --------------------------------------------------------
    # Initialize database
    # --------------------------------------------------------

    print("\n[2] Initializing database...")

    init_database()

    print("[OK] Database initialized.")

    # --------------------------------------------------------
    # Create scan
    # --------------------------------------------------------

    print("\n[3] Creating test scan...")

    with session_scope() as session:
        scan = Scan(
            target="example.com",
            scan_type="recon",
            status="completed",
        )

        session.add(scan)

    print("[OK] Scan created.")

    # --------------------------------------------------------
    # Retrieve scan
    # --------------------------------------------------------

    print("\n[4] Retrieving scan...")

    with session_scope() as session:
        scan = session.query(Scan).first()

        if scan is None:
            print("[FAIL] Scan was not found.")
            return

        print(f"[OK] {scan}")

    # --------------------------------------------------------
    # Create asset
    # --------------------------------------------------------

    print("\n[5] Creating asset...")

    with session_scope() as session:
        scan = session.query(Scan).first()

        asset = Asset(
            scan=scan,
            asset_type="domain",
            value="example.com",
            hostname="example.com",
        )

        session.add(asset)

    print("[OK] Asset created.")

    # --------------------------------------------------------
    # Test relationship
    # --------------------------------------------------------

    print("\n[6] Testing Scan → Asset relationship...")

    with session_scope() as session:
        scan = session.query(Scan).first()

        print(f"Scan: {scan}")
        print(f"Assets: {scan.assets}")

    print("\n" + "=" * 60)
    print("DATABASE TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()