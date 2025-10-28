"""
Database Layer for SOC AI Agents
Provides persistent storage for playbooks, approvals, and audit logs.
Supports PostgreSQL with SQLAlchemy ORM.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Boolean,
    Text, JSON, DateTime, ForeignKey, Index, Enum as SQLEnum, text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import QueuePool
import enum
import logging
import json

Base = declarative_base()
logger = logging.getLogger("Database")


class PlaybookStatus(enum.Enum):
    """Playbook execution status"""
    PENDING = "pending"
    DRY_RUN = "dry_run"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ApprovalStatus(enum.Enum):
    """Approval decision status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class UserRole(enum.Enum):
    """User roles for RBAC"""
    VIEWER = "viewer"          # Can view only
    ANALYST = "analyst"        # Can create playbooks
    APPROVER = "approver"      # Can approve playbooks
    EXECUTOR = "executor"      # Can execute approved playbooks
    ADMIN = "admin"            # Full access


class DBPlaybook(Base):
    """Persistent playbook record"""
    __tablename__ = 'playbooks'

    # Primary identification
    id = Column(String(64), primary_key=True)
    created_at = Column(DateTime, nullable=False, index=True)
    updated_at = Column(DateTime, nullable=False)

    # Playbook details
    action = Column(String(128), nullable=False, index=True)
    target = Column(String(256))
    justification = Column(Text, nullable=False)
    threat_type = Column(String(64), index=True)
    severity = Column(String(16), index=True)

    # Status and execution
    status = Column(SQLEnum(PlaybookStatus), nullable=False, default=PlaybookStatus.PENDING, index=True)
    dry_run_result = Column(JSON)
    execution_result = Column(JSON)
    error_message = Column(Text)

    # Ownership and audit
    created_by = Column(String(128), nullable=False, index=True)  # User who created it
    approved_by = Column(String(128), index=True)  # User who approved it
    executed_by = Column(String(128), index=True)  # System/user who executed it

    # Alert context
    alert_id = Column(String(64), index=True)
    agent_id = Column(String(128), index=True)

    # Metadata and signatures
    playbook_metadata = Column(JSON)  # Renamed to avoid SQLAlchemy conflict
    signature = Column(Text)  # Cryptographic signature
    signature_timestamp = Column(DateTime)

    # Retention
    expires_at = Column(DateTime, index=True)
    archived = Column(Boolean, default=False, index=True)

    # Relationships
    approvals = relationship("DBApproval", back_populates="playbook", cascade="all, delete-orphan")
    audit_logs = relationship("DBAuditLog", back_populates="playbook", cascade="all, delete-orphan")

    __table_args__ = (
        Index('ix_playbook_status_created', 'status', 'created_at'),
        Index('ix_playbook_alert_status', 'alert_id', 'status'),
    )


class DBApproval(Base):
    """Approval record for playbooks"""
    __tablename__ = 'approvals'

    id = Column(Integer, primary_key=True, autoincrement=True)
    playbook_id = Column(String(64), ForeignKey('playbooks.id'), nullable=False, index=True)

    # Approval details
    status = Column(SQLEnum(ApprovalStatus), nullable=False, default=ApprovalStatus.PENDING, index=True)
    requested_at = Column(DateTime, nullable=False, index=True)
    requested_by = Column(String(128), nullable=False, index=True)

    decided_at = Column(DateTime, index=True)
    decided_by = Column(String(128), index=True)

    decision_reason = Column(Text)
    expires_at = Column(DateTime, index=True)

    # Risk assessment
    risk_level = Column(String(16))  # low, medium, high, critical
    requires_multi_approval = Column(Boolean, default=False)

    # Cryptographic proof
    signature = Column(Text)  # Signature of approval decision
    signature_timestamp = Column(DateTime)

    # Metadata
    record_metadata = Column(JSON)  # Renamed to avoid SQLAlchemy conflict

    # Relationships
    playbook = relationship("DBPlaybook", back_populates="approvals")

    __table_args__ = (
        Index('ix_approval_status_requested', 'status', 'requested_at'),
        Index('ix_approval_playbook_status', 'playbook_id', 'status'),
    )


class DBAuditLog(Base):
    """Immutable audit log entry"""
    __tablename__ = 'audit_logs'

    # Append-only ID
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)

    # Event details
    event_type = Column(String(64), nullable=False, index=True)  # playbook_created, approved, executed, etc.
    action = Column(String(128), nullable=False)
    target = Column(String(256))

    # Context
    playbook_id = Column(String(64), ForeignKey('playbooks.id'), index=True)
    alert_id = Column(String(64), index=True)
    user_id = Column(String(128), nullable=False, index=True)
    user_role = Column(SQLEnum(UserRole))

    # Result
    success = Column(Boolean, index=True)
    error_message = Column(Text)

    # Data snapshot
    before_state = Column(JSON)
    after_state = Column(JSON)
    log_metadata = Column(JSON)  # Renamed to avoid SQLAlchemy conflict

    # Cryptographic integrity
    signature = Column(Text, nullable=False)  # HMAC or signature of the log entry
    signature_timestamp = Column(DateTime, nullable=False)
    previous_log_hash = Column(String(64))  # Hash chain for tamper detection

    # Relationships
    playbook = relationship("DBPlaybook", back_populates="audit_logs")

    __table_args__ = (
        Index('ix_audit_event_timestamp', 'event_type', 'timestamp'),
        Index('ix_audit_user_timestamp', 'user_id', 'timestamp'),
        Index('ix_audit_playbook_event', 'playbook_id', 'event_type'),
    )


class DBUser(Base):
    """User authentication and authorization"""
    __tablename__ = 'users'

    id = Column(String(128), primary_key=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, index=True)

    # Authentication
    password_hash = Column(String(256))  # For local auth
    oidc_subject = Column(String(256), unique=True, index=True)  # For OIDC

    # Authorization
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.VIEWER, index=True)
    permissions = Column(JSON)  # Additional fine-grained permissions

    # Status
    active = Column(Boolean, default=True, index=True)
    locked = Column(Boolean, default=False)

    # Audit
    created_at = Column(DateTime, nullable=False)
    last_login = Column(DateTime)
    last_activity = Column(DateTime)

    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(256))

    # Metadata
    record_metadata = Column(JSON)  # Renamed to avoid SQLAlchemy conflict

    __table_args__ = (
        Index('ix_user_role_active', 'role', 'active'),
    )


class DBSession(Base):
    """Active user sessions"""
    __tablename__ = 'sessions'

    id = Column(String(128), primary_key=True)
    user_id = Column(String(128), ForeignKey('users.id'), nullable=False, index=True)

    # Session details
    created_at = Column(DateTime, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_activity = Column(DateTime, nullable=False)

    # Context
    ip_address = Column(String(64))
    user_agent = Column(String(512))

    # Security
    token_hash = Column(String(256), unique=True, nullable=False)
    revoked = Column(Boolean, default=False, index=True)

    # Metadata
    record_metadata = Column(JSON)  # Renamed to avoid SQLAlchemy conflict


class DatabaseManager:
    """Manages database connections and operations"""

    def __init__(self, database_url: str = "postgresql://soc:soc_password@localhost:5432/soc_db"):
        """
        Initialize database connection.

        Args:
            database_url: PostgreSQL connection URL
                Format: postgresql://user:password@host:port/database
        """
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,  # Verify connections before using
            echo=False  # Set to True for SQL debugging
        )
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        logger.info(f"Database manager initialized with URL: {database_url.split('@')[1] if '@' in database_url else 'N/A'}")

    def create_all_tables(self):
        """Create all tables in the database"""
        Base.metadata.create_all(bind=self.engine)
        logger.info("All database tables created successfully")

    def drop_all_tables(self):
        """Drop all tables (use with caution!)"""
        Base.metadata.drop_all(bind=self.engine)
        logger.warning("All database tables dropped")

    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()

    def health_check(self) -> bool:
        """Check if database is accessible"""
        try:
            session = self.get_session()
            session.execute(text("SELECT 1"))
            session.close()
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    def cleanup_expired_records(self, session: Session):
        """Remove expired records based on retention policies"""
        now = datetime.utcnow()

        # Archive old playbooks
        expired_playbooks = session.query(DBPlaybook).filter(
            DBPlaybook.expires_at < now,
            DBPlaybook.archived == False
        ).all()

        for playbook in expired_playbooks:
            playbook.archived = True
            logger.info(f"Archived expired playbook: {playbook.id}")

        # Clean expired sessions
        expired_sessions = session.query(DBSession).filter(
            DBSession.expires_at < now,
            DBSession.revoked == False
        ).all()

        for sess in expired_sessions:
            sess.revoked = True
            logger.info(f"Revoked expired session: {sess.id}")

        # Expire old approval requests
        expired_approvals = session.query(DBApproval).filter(
            DBApproval.status == ApprovalStatus.PENDING,
            DBApproval.expires_at < now
        ).all()

        for approval in expired_approvals:
            approval.status = ApprovalStatus.EXPIRED
            logger.info(f"Expired approval request: {approval.id}")

        session.commit()

    def export_audit_logs(
        self,
        session: Session,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Export audit logs for forensic analysis.

        Args:
            session: Database session
            start_date: Filter by start date
            end_date: Filter by end date
            user_id: Filter by user
            event_type: Filter by event type

        Returns:
            List of audit log records as dictionaries
        """
        query = session.query(DBAuditLog)

        if start_date:
            query = query.filter(DBAuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(DBAuditLog.timestamp <= end_date)
        if user_id:
            query = query.filter(DBAuditLog.user_id == user_id)
        if event_type:
            query = query.filter(DBAuditLog.event_type == event_type)

        query = query.order_by(DBAuditLog.timestamp.asc())

        logs = []
        for log in query.all():
            logs.append({
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'event_type': log.event_type,
                'action': log.action,
                'target': log.target,
                'playbook_id': log.playbook_id,
                'alert_id': log.alert_id,
                'user_id': log.user_id,
                'user_role': log.user_role.value if log.user_role else None,
                'success': log.success,
                'error_message': log.error_message,
                'before_state': log.before_state,
                'after_state': log.after_state,
                'metadata': log.log_metadata,
                'signature': log.signature,
                'signature_timestamp': log.signature_timestamp.isoformat() if log.signature_timestamp else None,
                'previous_log_hash': log.previous_log_hash
            })

        logger.info(f"Exported {len(logs)} audit log records")
        return logs


# Convenience functions for common operations
def create_playbook_record(
    session: Session,
    playbook_id: str,
    action: str,
    target: str,
    justification: str,
    created_by: str,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    alert_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    expires_in_days: int = 90
) -> DBPlaybook:
    """Create a new playbook record"""
    now = datetime.utcnow()
    expires_at = now + timedelta(days=expires_in_days)

    playbook = DBPlaybook(
        id=playbook_id,
        created_at=now,
        updated_at=now,
        action=action,
        target=target,
        justification=justification,
        threat_type=threat_type,
        severity=severity,
        status=PlaybookStatus.DRY_RUN,  # Default to dry-run
        created_by=created_by,
        alert_id=alert_id,
        agent_id=agent_id,
        playbook_metadata=metadata or {},
        expires_at=expires_at
    )

    session.add(playbook)
    return playbook


def create_audit_log(
    session: Session,
    event_type: str,
    action: str,
    user_id: str,
    user_role: UserRole,
    success: bool,
    signature: str,
    target: Optional[str] = None,
    playbook_id: Optional[str] = None,
    alert_id: Optional[str] = None,
    error_message: Optional[str] = None,
    before_state: Optional[Dict] = None,
    after_state: Optional[Dict] = None,
    metadata: Optional[Dict] = None,
    previous_log_hash: Optional[str] = None
) -> DBAuditLog:
    """Create an immutable audit log entry"""
    now = datetime.utcnow()

    audit_log = DBAuditLog(
        timestamp=now,
        event_type=event_type,
        action=action,
        target=target,
        playbook_id=playbook_id,
        alert_id=alert_id,
        user_id=user_id,
        user_role=user_role,
        success=success,
        error_message=error_message,
        before_state=before_state,
        after_state=after_state,
        log_metadata=metadata,
        signature=signature,
        signature_timestamp=now,
        previous_log_hash=previous_log_hash
    )

    session.add(audit_log)
    return audit_log
