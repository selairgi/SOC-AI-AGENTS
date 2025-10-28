"""
Database Setup and Migration Script
Creates tables, default users, and initializes the system.
"""

import sys
import argparse
import logging
from datetime import datetime

from database import DatabaseManager, PlaybookStatus, ApprovalStatus, UserRole
from auth_rbac import AuthManager, create_default_users
from crypto_signing import CryptoSigner
from policy_engine import PolicyEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DatabaseSetup")


def setup_database(database_url: str, drop_existing: bool = False):
    """
    Set up database with all tables and default data.

    Args:
        database_url: PostgreSQL connection URL
        drop_existing: If True, drop all existing tables first (DANGEROUS!)
    """
    logger.info("=" * 70)
    logger.info("SOC AI AGENTS - DATABASE SETUP")
    logger.info("=" * 70)

    # Initialize database manager
    logger.info(f"Connecting to database...")
    db_manager = DatabaseManager(database_url)

    # Health check
    if not db_manager.health_check():
        logger.error("Database health check failed. Please verify connection settings.")
        sys.exit(1)

    logger.info("✓ Database connection successful")

    # Drop tables if requested
    if drop_existing:
        logger.warning("⚠️  DROP EXISTING TABLES requested!")
        confirm = input("This will DELETE ALL DATA. Type 'yes' to continue: ")
        if confirm.lower() != 'yes':
            logger.info("Aborted.")
            sys.exit(0)

        logger.info("Dropping all tables...")
        db_manager.drop_all_tables()
        logger.info("✓ All tables dropped")

    # Create tables
    logger.info("Creating database tables...")
    db_manager.create_all_tables()
    logger.info("✓ Database tables created successfully")

    # Initialize authentication manager
    logger.info("Initializing authentication system...")
    auth_manager = AuthManager(db_manager)
    logger.info("✓ Authentication system initialized")

    # Create default users
    logger.info("Creating default users...")
    create_default_users(auth_manager)
    logger.info("✓ Default users created:")
    logger.info("  - admin / admin_password_change_me (ADMIN)")
    logger.info("  - analyst / analyst_password (ANALYST)")
    logger.info("  - approver / approver_password (APPROVER)")
    logger.info("  - executor / executor_password (EXECUTOR)")

    # Initialize policy engine
    logger.info("Initializing policy engine...")
    policy_engine = PolicyEngine()
    logger.info(f"✓ Policy engine initialized with {len(policy_engine.rules)} default policies")

    # Initialize crypto signer
    logger.info("Initializing cryptographic signer...")
    crypto_signer = CryptoSigner()
    logger.info("✓ Cryptographic signer initialized")

    logger.info("=" * 70)
    logger.info("DATABASE SETUP COMPLETE!")
    logger.info("=" * 70)
    logger.info("")
    logger.info("Next steps:")
    logger.info("1. Change default passwords:")
    logger.info("   python -c \"from auth_rbac import *; ...\"")
    logger.info("2. Configure environment variables in .env")
    logger.info("3. Start the web application:")
    logger.info("   python enhanced_web_chatbot.py")
    logger.info("")
    logger.info("⚠️  SECURITY REMINDER:")
    logger.info("   - Change all default passwords immediately")
    logger.info("   - Use strong passwords in production")
    logger.info("   - Enable HTTPS for production deployment")
    logger.info("   - Configure OIDC for enterprise authentication")
    logger.info("")


def verify_setup(database_url: str):
    """Verify database setup"""
    logger.info("Verifying database setup...")

    db_manager = DatabaseManager(database_url)

    if not db_manager.health_check():
        logger.error("❌ Database health check failed")
        return False

    session = db_manager.get_session()
    try:
        from database import DBUser

        # Check if users exist
        user_count = session.query(DBUser).count()
        if user_count == 0:
            logger.error("❌ No users found in database")
            return False

        logger.info(f"✓ Found {user_count} users")

        # List users
        users = session.query(DBUser).all()
        logger.info("Users:")
        for user in users:
            logger.info(f"  - {user.username} ({user.role.value})")

        logger.info("✓ Database setup verified successfully")
        return True

    except Exception as e:
        logger.error(f"❌ Verification failed: {e}")
        return False
    finally:
        session.close()


def export_schema(database_url: str, output_file: str):
    """Export database schema to SQL file"""
    logger.info(f"Exporting schema to {output_file}...")

    from database import Base
    from sqlalchemy import create_engine
    from sqlalchemy.schema import CreateTable

    engine = create_engine(database_url, echo=False)

    with open(output_file, 'w') as f:
        f.write("-- SOC AI Agents Database Schema\n")
        f.write(f"-- Generated: {datetime.utcnow().isoformat()}\n")
        f.write("-- \n\n")

        for table in Base.metadata.sorted_tables:
            f.write(f"-- Table: {table.name}\n")
            f.write(str(CreateTable(table).compile(engine)) + ";\n\n")

    logger.info(f"✓ Schema exported to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="SOC AI Agents Database Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initial setup with local PostgreSQL
  python setup_database.py setup --url "postgresql://soc:soc_password@localhost:5432/soc_db"

  # Setup with drop existing (DANGEROUS!)
  python setup_database.py setup --url "..." --drop-existing

  # Verify setup
  python setup_database.py verify --url "..."

  # Export schema
  python setup_database.py export-schema --url "..." --output schema.sql

Default PostgreSQL URL:
  postgresql://soc:soc_password@localhost:5432/soc_db

Before running:
  1. Install PostgreSQL
  2. Create database: createdb soc_db
  3. Create user: createuser -P soc
  4. Grant privileges: GRANT ALL PRIVILEGES ON DATABASE soc_db TO soc;
        """
    )

    parser.add_argument(
        'command',
        choices=['setup', 'verify', 'export-schema'],
        help='Command to execute'
    )

    parser.add_argument(
        '--url',
        default='postgresql://soc:soc_password@localhost:5432/soc_db',
        help='PostgreSQL connection URL (default: local database)'
    )

    parser.add_argument(
        '--drop-existing',
        action='store_true',
        help='Drop existing tables (DANGEROUS! Will delete all data)'
    )

    parser.add_argument(
        '--output',
        default='schema.sql',
        help='Output file for schema export'
    )

    args = parser.parse_args()

    try:
        if args.command == 'setup':
            setup_database(args.url, args.drop_existing)
        elif args.command == 'verify':
            success = verify_setup(args.url)
            sys.exit(0 if success else 1)
        elif args.command == 'export-schema':
            export_schema(args.url, args.output)

    except KeyboardInterrupt:
        logger.info("\nAborted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
