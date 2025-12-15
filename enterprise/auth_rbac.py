"""
Authentication and Role-Based Access Control (RBAC)
Supports OIDC, local authentication, and fine-grained permissions.
"""

import secrets
import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from functools import wraps
from dataclasses import dataclass

from .database import (
    DatabaseManager, DBUser, DBSession, UserRole,
    PlaybookStatus, ApprovalStatus
)

logger = logging.getLogger("AuthRBAC")


@dataclass
class Permission:
    """Fine-grained permission"""
    resource: str  # playbook, approval, user, audit_log
    action: str    # create, read, update, delete, approve, execute
    conditions: Optional[Dict[str, Any]] = None  # Additional conditions


@dataclass
class AuthContext:
    """Authentication context for a request"""
    user_id: str
    username: str
    role: UserRole
    permissions: List[Permission]
    session_id: str
    ip_address: Optional[str] = None


# Role-based permission matrix
ROLE_PERMISSIONS = {
    UserRole.VIEWER: [
        Permission("playbook", "read"),
        Permission("approval", "read"),
        Permission("audit_log", "read"),
    ],
    UserRole.ANALYST: [
        Permission("playbook", "read"),
        Permission("playbook", "create"),
        Permission("approval", "read"),
        Permission("approval", "request"),
        Permission("audit_log", "read"),
    ],
    UserRole.APPROVER: [
        Permission("playbook", "read"),
        Permission("approval", "read"),
        Permission("approval", "approve"),
        Permission("approval", "reject"),
        Permission("audit_log", "read"),
    ],
    UserRole.EXECUTOR: [
        Permission("playbook", "read"),
        Permission("playbook", "execute", {"conditions": {"status": "approved"}}),
        Permission("approval", "read"),
        Permission("audit_log", "read"),
    ],
    UserRole.ADMIN: [
        Permission("playbook", "read"),
        Permission("playbook", "create"),
        Permission("playbook", "update"),
        Permission("playbook", "delete"),
        Permission("playbook", "execute"),
        Permission("approval", "read"),
        Permission("approval", "request"),
        Permission("approval", "approve"),
        Permission("approval", "reject"),
        Permission("user", "read"),
        Permission("user", "create"),
        Permission("user", "update"),
        Permission("user", "delete"),
        Permission("audit_log", "read"),
        Permission("audit_log", "export"),
    ],
}


class AuthenticationError(Exception):
    """Authentication failed"""
    pass


class AuthorizationError(Exception):
    """Authorization failed"""
    pass


class AuthManager:
    """Manages authentication and authorization"""

    def __init__(self, db_manager: DatabaseManager, secret_key: Optional[str] = None):
        self.db = db_manager
        self.secret_key = secret_key or secrets.token_hex(32)
        self.session_timeout = timedelta(hours=8)
        self.token_cache = {}  # Simple in-memory cache for token validation
        logger.info("Authentication manager initialized")

    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)

        # Use PBKDF2 for password hashing
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        ).hex()

        return f"{salt}${password_hash}", salt

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, password_hash = stored_hash.split('$')
            new_hash, _ = self.hash_password(password, salt)
            return hmac.compare_digest(new_hash, stored_hash)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    def create_user(
        self,
        username: str,
        email: str,
        role: UserRole,
        password: Optional[str] = None,
        oidc_subject: Optional[str] = None
    ) -> DBUser:
        """Create a new user"""
        session = self.db.get_session()
        try:
            # Check if user already exists
            existing = session.query(DBUser).filter(
                (DBUser.username == username) | (DBUser.email == email)
            ).first()

            if existing:
                raise ValueError(f"User with username '{username}' or email '{email}' already exists")

            user_id = secrets.token_hex(16)
            password_hash = None

            if password:
                password_hash, _ = self.hash_password(password)

            user = DBUser(
                id=user_id,
                username=username,
                email=email,
                role=role,
                password_hash=password_hash,
                oidc_subject=oidc_subject,
                active=True,
                created_at=datetime.utcnow(),
                permissions={}
            )

            session.add(user)
            session.commit()
            logger.info(f"Created user: {username} with role {role.value}")
            return user

        finally:
            session.close()

    def authenticate_local(self, username: str, password: str, ip_address: Optional[str] = None) -> AuthContext:
        """Authenticate user with username/password"""
        session = self.db.get_session()
        try:
            user = session.query(DBUser).filter(
                DBUser.username == username,
                DBUser.active == True,
                DBUser.locked == False
            ).first()

            if not user or not user.password_hash:
                raise AuthenticationError("Invalid credentials")

            if not self.verify_password(password, user.password_hash):
                raise AuthenticationError("Invalid credentials")

            # Create session
            auth_context = self._create_session(user, ip_address, session)

            # Update last login
            user.last_login = datetime.utcnow()
            user.last_activity = datetime.utcnow()
            session.commit()

            logger.info(f"User {username} authenticated successfully")
            return auth_context

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise AuthenticationError("Authentication failed")
        finally:
            session.close()

    def authenticate_oidc(self, oidc_subject: str, id_token: Dict[str, Any], ip_address: Optional[str] = None) -> AuthContext:
        """
        Authenticate user via OIDC.

        Args:
            oidc_subject: Subject from OIDC token
            id_token: Decoded and verified OIDC ID token
            ip_address: Client IP address

        Returns:
            AuthContext
        """
        session = self.db.get_session()
        try:
            user = session.query(DBUser).filter(
                DBUser.oidc_subject == oidc_subject,
                DBUser.active == True,
                DBUser.locked == False
            ).first()

            if not user:
                # Auto-provision user from OIDC claims
                user = self._provision_oidc_user(oidc_subject, id_token, session)

            # Create session
            auth_context = self._create_session(user, ip_address, session)

            # Update last login
            user.last_login = datetime.utcnow()
            user.last_activity = datetime.utcnow()
            session.commit()

            logger.info(f"User {user.username} authenticated via OIDC")
            return auth_context

        except Exception as e:
            logger.error(f"OIDC authentication error: {e}")
            raise AuthenticationError("OIDC authentication failed")
        finally:
            session.close()

    def _provision_oidc_user(self, oidc_subject: str, id_token: Dict[str, Any], session) -> DBUser:
        """Auto-provision user from OIDC claims"""
        username = id_token.get('preferred_username', id_token.get('email', oidc_subject))
        email = id_token.get('email', f"{oidc_subject}@oidc.local")

        # Default role for OIDC users
        role = UserRole.VIEWER

        # Check for role claims
        if 'roles' in id_token:
            roles = id_token['roles']
            if 'soc-admin' in roles:
                role = UserRole.ADMIN
            elif 'soc-approver' in roles:
                role = UserRole.APPROVER
            elif 'soc-analyst' in roles:
                role = UserRole.ANALYST

        user_id = secrets.token_hex(16)
        user = DBUser(
            id=user_id,
            username=username,
            email=email,
            role=role,
            oidc_subject=oidc_subject,
            active=True,
            created_at=datetime.utcnow(),
            permissions={}
        )

        session.add(user)
        logger.info(f"Auto-provisioned OIDC user: {username} with role {role.value}")
        return user

    def _create_session(self, user: DBUser, ip_address: Optional[str], session) -> AuthContext:
        """Create a new session for authenticated user"""
        session_id = secrets.token_urlsafe(32)
        token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        now = datetime.utcnow()
        expires_at = now + self.session_timeout

        db_session = DBSession(
            id=session_id,
            user_id=user.id,
            created_at=now,
            expires_at=expires_at,
            last_activity=now,
            ip_address=ip_address,
            token_hash=token_hash,
            revoked=False
        )

        session.add(db_session)

        # Cache token
        self.token_cache[token] = {
            'session_id': session_id,
            'user_id': user.id,
            'expires_at': expires_at
        }

        # Create auth context
        permissions = ROLE_PERMISSIONS.get(user.role, [])

        return AuthContext(
            user_id=user.id,
            username=user.username,
            role=user.role,
            permissions=permissions,
            session_id=session_id,
            ip_address=ip_address
        )

    def validate_token(self, token: str) -> AuthContext:
        """Validate session token and return auth context"""
        # Check cache first
        if token in self.token_cache:
            cached = self.token_cache[token]
            if cached['expires_at'] > datetime.utcnow():
                return self._get_auth_context(cached['user_id'], cached['session_id'])
            else:
                del self.token_cache[token]

        # Check database
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session = self.db.get_session()
        try:
            db_session = session.query(DBSession).filter(
                DBSession.token_hash == token_hash,
                DBSession.revoked == False,
                DBSession.expires_at > datetime.utcnow()
            ).first()

            if not db_session:
                raise AuthenticationError("Invalid or expired token")

            # Update last activity
            db_session.last_activity = datetime.utcnow()
            session.commit()

            return self._get_auth_context(db_session.user_id, db_session.id)

        finally:
            session.close()

    def _get_auth_context(self, user_id: str, session_id: str) -> AuthContext:
        """Get auth context for user"""
        session = self.db.get_session()
        try:
            user = session.query(DBUser).filter(DBUser.id == user_id).first()
            if not user or not user.active:
                raise AuthenticationError("User not found or inactive")

            permissions = ROLE_PERMISSIONS.get(user.role, [])

            return AuthContext(
                user_id=user.id,
                username=user.username,
                role=user.role,
                permissions=permissions,
                session_id=session_id
            )
        finally:
            session.close()

    def revoke_session(self, session_id: str):
        """Revoke a session"""
        session = self.db.get_session()
        try:
            db_session = session.query(DBSession).filter(DBSession.id == session_id).first()
            if db_session:
                db_session.revoked = True
                session.commit()
                logger.info(f"Revoked session: {session_id}")
        finally:
            session.close()

    def check_permission(
        self,
        auth_context: AuthContext,
        resource: str,
        action: str,
        resource_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check if user has permission to perform action on resource.

        Args:
            auth_context: User's authentication context
            resource: Resource type (playbook, approval, etc.)
            action: Action to perform (create, read, update, delete, etc.)
            resource_data: Additional data about the resource for condition checking

        Returns:
            True if authorized, False otherwise
        """
        # Admin has all permissions
        if auth_context.role == UserRole.ADMIN:
            return True

        # Check permissions
        for perm in auth_context.permissions:
            if perm.resource == resource and perm.action == action:
                # Check conditions if present
                if perm.conditions and resource_data:
                    for key, value in perm.conditions.items():
                        if key == "conditions" and isinstance(value, dict):
                            for cond_key, cond_value in value.items():
                                if resource_data.get(cond_key) != cond_value:
                                    continue
                        elif resource_data.get(key) != value:
                            continue
                return True

        return False

    def require_permission(self, resource: str, action: str):
        """
        Decorator to require permission for a function.

        Usage:
            @auth_manager.require_permission("playbook", "create")
            def create_playbook(auth_context, ...):
                ...
        """
        def decorator(func):
            @wraps(func)
            def wrapper(auth_context: AuthContext, *args, **kwargs):
                if not self.check_permission(auth_context, resource, action):
                    raise AuthorizationError(
                        f"User {auth_context.username} does not have permission to {action} {resource}"
                    )
                return func(auth_context, *args, **kwargs)
            return wrapper
        return decorator


def create_default_users(auth_manager: AuthManager):
    """Create default users for testing"""
    try:
        # Admin user
        auth_manager.create_user(
            username="admin",
            email="admin@soc.local",
            role=UserRole.ADMIN,
            password="admin_password_change_me"
        )
        logger.info("Created default admin user")

        # Analyst user
        auth_manager.create_user(
            username="analyst",
            email="analyst@soc.local",
            role=UserRole.ANALYST,
            password="analyst_password"
        )
        logger.info("Created default analyst user")

        # Approver user
        auth_manager.create_user(
            username="approver",
            email="approver@soc.local",
            role=UserRole.APPROVER,
            password="approver_password"
        )
        logger.info("Created default approver user")

        # Executor user
        auth_manager.create_user(
            username="executor",
            email="executor@soc.local",
            role=UserRole.EXECUTOR,
            password="executor_password"
        )
        logger.info("Created default executor user")

    except ValueError as e:
        logger.info(f"Default users may already exist: {e}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Initialize
    db_manager = DatabaseManager("postgresql://soc:soc_password@localhost:5432/soc_db")
    db_manager.create_all_tables()

    auth_manager = AuthManager(db_manager)
    create_default_users(auth_manager)

    # Test authentication
    try:
        auth_context = auth_manager.authenticate_local("admin", "admin_password_change_me")
        print(f"Authenticated: {auth_context.username} with role {auth_context.role.value}")

        # Test permission check
        can_create = auth_manager.check_permission(auth_context, "playbook", "create")
        print(f"Can create playbook: {can_create}")

    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
