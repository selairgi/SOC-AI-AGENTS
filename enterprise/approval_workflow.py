"""
Approval Workflow System with Dry-Run Mode
Implements approval gating for destructive actions with cryptographic signatures.
Dry-run is the default for all new playbooks.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import secrets

from .database import (
    DatabaseManager, DBPlaybook, DBApproval, DBAuditLog,
    PlaybookStatus, ApprovalStatus, UserRole,
    create_playbook_record, create_audit_log
)
from .auth_rbac import AuthContext, AuthManager, AuthorizationError
from .crypto_signing import CryptoSigner, PlaybookSigner, ApprovalSigner, AuditLogChain
from .policy_engine import PolicyEngine, PolicyDecision

logger = logging.getLogger("ApprovalWorkflow")


@dataclass
class DryRunResult:
    """Result of dry-run execution"""
    success: bool
    actions_validated: List[Dict[str, Any]]
    errors: List[str]
    warnings: List[str]
    estimated_impact: Dict[str, Any]


@dataclass
class PlaybookExecutionResult:
    """Result of actual playbook execution"""
    success: bool
    actions_executed: List[Dict[str, Any]]
    errors: List[str]
    execution_time: float


class ApprovalWorkflowManager:
    """Manages approval workflow for playbooks"""

    def __init__(
        self,
        db_manager: DatabaseManager,
        auth_manager: AuthManager,
        crypto_signer: CryptoSigner,
        policy_engine: PolicyEngine
    ):
        self.db = db_manager
        self.auth = auth_manager
        self.signer = crypto_signer
        self.policy_engine = policy_engine

        self.playbook_signer = PlaybookSigner(crypto_signer)
        self.approval_signer = ApprovalSigner(crypto_signer)
        self.audit_chain = AuditLogChain(crypto_signer)

        self.approval_timeout = timedelta(hours=24)  # Approvals expire after 24 hours

        logger.info("Approval workflow manager initialized")

    def create_playbook(
        self,
        auth_context: AuthContext,
        action: str,
        target: str,
        justification: str,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        alert_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        environment: str = "production"
    ) -> DBPlaybook:
        """
        Create a new playbook (defaults to dry-run mode).

        Args:
            auth_context: Authentication context
            action: Remediation action to perform
            target: Target of the action
            justification: Reason for the action
            threat_type: Type of threat
            severity: Alert severity
            alert_id: Associated alert ID
            agent_id: Associated agent ID
            metadata: Additional metadata
            environment: Environment (production, development, etc.)

        Returns:
            Created playbook

        Raises:
            AuthorizationError: If user lacks permission
            ValidationError: If policy denies the action
        """
        # Check permission
        if not self.auth.check_permission(auth_context, "playbook", "create"):
            raise AuthorizationError(f"User {auth_context.username} cannot create playbooks")

        # Evaluate policies
        policy_context = {
            'action': action,
            'target': target,
            'environment': environment,
            'severity': severity,
            'is_new_playbook': True,
            'has_approval': False,
            'created_by': auth_context.user_id,
            'metadata': metadata
        }

        policy_result = self.policy_engine.evaluate(policy_context)

        # DENY = reject immediately
        if policy_result.decision == PolicyDecision.DENY:
            logger.warning(f"Policy denied playbook creation: {policy_result.reasons}")
            raise ValidationError(f"Policy denied: {'; '.join(policy_result.reasons)}")

        # Generate playbook ID
        playbook_id = f"pb_{secrets.token_hex(16)}"

        # Sign the playbook
        sig_result = self.playbook_signer.sign_playbook(
            playbook_id=playbook_id,
            action=action,
            target=target,
            justification=justification,
            created_by=auth_context.user_id,
            threat_type=threat_type,
            metadata=metadata
        )

        # Create database session
        session = self.db.get_session()
        try:
            # Create playbook record (default status is DRY_RUN)
            playbook = create_playbook_record(
                session=session,
                playbook_id=playbook_id,
                action=action,
                target=target,
                justification=justification,
                created_by=auth_context.user_id,
                threat_type=threat_type,
                severity=severity,
                alert_id=alert_id,
                agent_id=agent_id,
                metadata={
                    **(metadata or {}),
                    'policy_result': {
                        'decision': policy_result.decision.value,
                        'reasons': policy_result.reasons,
                        'matched_policies': policy_result.matched_policies
                    },
                    'environment': environment
                }
            )

            # Add signature
            playbook.signature = sig_result.signature
            playbook.signature_timestamp = sig_result.timestamp

            # Set status based on policy
            if policy_result.decision == PolicyDecision.REQUIRE_APPROVAL:
                playbook.status = PlaybookStatus.PENDING
            else:
                playbook.status = PlaybookStatus.DRY_RUN

            # Create audit log
            log_data, log_sig, prev_hash = self.audit_chain.create_log_entry(
                event_type="playbook_created",
                action=action,
                user_id=auth_context.user_id,
                user_role=auth_context.role.value,
                success=True,
                playbook_id=playbook_id,
                alert_id=alert_id,
                target=target,
                metadata={
                    'policy_decision': policy_result.decision.value,
                    'requires_approval': policy_result.requires_approval
                }
            )

            audit_log = create_audit_log(
                session=session,
                event_type="playbook_created",
                action=action,
                user_id=auth_context.user_id,
                user_role=auth_context.role,
                success=True,
                signature=log_sig,
                target=target,
                playbook_id=playbook_id,
                alert_id=alert_id,
                metadata=log_data.get('metadata'),
                previous_log_hash=prev_hash
            )

            session.commit()

            # Refresh playbook to make sure all attributes are loaded
            session.refresh(playbook)

            logger.info(f"Created playbook {playbook_id} by {auth_context.username}")

            # Auto-request approval if needed
            if policy_result.requires_approval:
                self._request_approval(playbook, auth_context, session)
                session.commit()
                session.refresh(playbook)

            # Make object accessible after session close
            session.expunge(playbook)

            return playbook

        finally:
            session.close()

    def _request_approval(self, playbook: DBPlaybook, auth_context: AuthContext, session):
        """Request approval for a playbook"""
        approval = DBApproval(
            playbook_id=playbook.id,
            status=ApprovalStatus.PENDING,
            requested_at=datetime.utcnow(),
            requested_by=auth_context.user_id,
            expires_at=datetime.utcnow() + self.approval_timeout,
            risk_level=playbook.severity or "medium",
            requires_multi_approval=False  # Can be extended for high-risk actions
        )

        session.add(approval)
        logger.info(f"Requested approval for playbook {playbook.id}")

    def execute_dry_run(
        self,
        auth_context: AuthContext,
        playbook_id: str
    ) -> DryRunResult:
        """
        Execute playbook in dry-run mode (simulation).

        Args:
            auth_context: Authentication context
            playbook_id: ID of playbook to dry-run

        Returns:
            DryRunResult with validation results

        Raises:
            AuthorizationError: If user lacks permission
        """
        # Check permission
        if not self.auth.check_permission(auth_context, "playbook", "read"):
            raise AuthorizationError(f"User {auth_context.username} cannot read playbooks")

        session = self.db.get_session()
        try:
            playbook = session.query(DBPlaybook).filter(DBPlaybook.id == playbook_id).first()
            if not playbook:
                raise ValueError(f"Playbook {playbook_id} not found")

            # Simulate execution
            actions_validated = []
            errors = []
            warnings = []

            # Parse actions from playbook
            actions = self._parse_playbook_actions(playbook)

            for action_def in actions:
                # Validate each action
                validation = self._validate_action(action_def)
                if validation['valid']:
                    actions_validated.append(action_def)
                else:
                    errors.append(validation['error'])

                if validation.get('warning'):
                    warnings.append(validation['warning'])

            # Estimate impact
            estimated_impact = {
                'total_actions': len(actions),
                'valid_actions': len(actions_validated),
                'failed_actions': len(errors),
                'estimated_duration': len(actions) * 0.5,  # seconds
                'affected_entities': self._estimate_affected_entities(actions_validated)
            }

            # Update playbook with dry-run result
            dry_run_result = {
                'executed_at': datetime.utcnow().isoformat(),
                'executed_by': auth_context.user_id,
                'success': len(errors) == 0,
                'actions_validated': len(actions_validated),
                'errors': errors,
                'warnings': warnings,
                'estimated_impact': estimated_impact
            }

            playbook.dry_run_result = dry_run_result
            playbook.updated_at = datetime.utcnow()

            # Create audit log
            log_data, log_sig, prev_hash = self.audit_chain.create_log_entry(
                event_type="dry_run_executed",
                action=playbook.action,
                user_id=auth_context.user_id,
                user_role=auth_context.role.value,
                success=len(errors) == 0,
                playbook_id=playbook_id,
                target=playbook.target,
                metadata=dry_run_result
            )

            create_audit_log(
                session=session,
                event_type="dry_run_executed",
                action=playbook.action,
                user_id=auth_context.user_id,
                user_role=auth_context.role,
                success=len(errors) == 0,
                signature=log_sig,
                playbook_id=playbook_id,
                target=playbook.target,
                metadata=log_data.get('metadata'),
                previous_log_hash=prev_hash
            )

            session.commit()
            logger.info(f"Dry-run executed for playbook {playbook_id}")

            return DryRunResult(
                success=len(errors) == 0,
                actions_validated=actions_validated,
                errors=errors,
                warnings=warnings,
                estimated_impact=estimated_impact
            )

        finally:
            session.close()

    def approve_playbook(
        self,
        auth_context: AuthContext,
        playbook_id: str,
        decision_reason: Optional[str] = None
    ) -> DBApproval:
        """
        Approve a playbook for execution.

        Args:
            auth_context: Authentication context
            playbook_id: ID of playbook to approve
            decision_reason: Reason for approval

        Returns:
            Approval record

        Raises:
            AuthorizationError: If user lacks permission
        """
        # Check permission
        if not self.auth.check_permission(auth_context, "approval", "approve"):
            raise AuthorizationError(f"User {auth_context.username} cannot approve playbooks")

        session = self.db.get_session()
        try:
            playbook = session.query(DBPlaybook).filter(DBPlaybook.id == playbook_id).first()
            if not playbook:
                raise ValueError(f"Playbook {playbook_id} not found")

            # Get pending approval
            approval = session.query(DBApproval).filter(
                DBApproval.playbook_id == playbook_id,
                DBApproval.status == ApprovalStatus.PENDING
            ).first()

            if not approval:
                raise ValueError(f"No pending approval for playbook {playbook_id}")

            # Check if approval is expired
            if approval.expires_at < datetime.utcnow():
                approval.status = ApprovalStatus.EXPIRED
                session.commit()
                raise ValueError(f"Approval request has expired")

            # Sign the approval
            sig_result = self.approval_signer.sign_approval(
                playbook_id=playbook_id,
                status="approved",
                decided_by=auth_context.user_id,
                decision_reason=decision_reason
            )

            # Update approval
            approval.status = ApprovalStatus.APPROVED
            approval.decided_at = datetime.utcnow()
            approval.decided_by = auth_context.user_id
            approval.decision_reason = decision_reason
            approval.signature = sig_result.signature
            approval.signature_timestamp = sig_result.timestamp

            # Update playbook
            playbook.status = PlaybookStatus.APPROVED
            playbook.approved_by = auth_context.user_id
            playbook.updated_at = datetime.utcnow()

            # Create audit log
            log_data, log_sig, prev_hash = self.audit_chain.create_log_entry(
                event_type="playbook_approved",
                action=playbook.action,
                user_id=auth_context.user_id,
                user_role=auth_context.role.value,
                success=True,
                playbook_id=playbook_id,
                target=playbook.target,
                before_state={'status': PlaybookStatus.PENDING.value},
                after_state={'status': PlaybookStatus.APPROVED.value},
                metadata={'decision_reason': decision_reason}
            )

            create_audit_log(
                session=session,
                event_type="playbook_approved",
                action=playbook.action,
                user_id=auth_context.user_id,
                user_role=auth_context.role,
                success=True,
                signature=log_sig,
                playbook_id=playbook_id,
                target=playbook.target,
                before_state={'status': PlaybookStatus.PENDING.value},
                after_state={'status': PlaybookStatus.APPROVED.value},
                metadata=log_data.get('metadata'),
                previous_log_hash=prev_hash
            )

            session.commit()

            # Refresh to load all attributes
            session.refresh(approval)
            session.refresh(playbook)

            # Make objects accessible after session close
            session.expunge(approval)
            session.expunge(playbook)

            logger.info(f"Playbook {playbook_id} approved by {auth_context.username}")

            return approval

        finally:
            session.close()

    def reject_playbook(
        self,
        auth_context: AuthContext,
        playbook_id: str,
        decision_reason: str
    ) -> DBApproval:
        """Reject a playbook"""
        # Similar to approve_playbook but sets status to REJECTED
        # Implementation follows same pattern
        pass  # Abbreviated for brevity

    def _parse_playbook_actions(self, playbook: DBPlaybook) -> List[Dict[str, Any]]:
        """Parse actions from playbook metadata"""
        metadata = playbook.playbook_metadata or {}
        actions = metadata.get('actions', [])

        if not actions:
            # Single action playbook
            return [{
                'action': playbook.action,
                'target': playbook.target
            }]

        # Multi-action playbook
        parsed = []
        for action_str in actions:
            if ':' in action_str:
                action_type, action_target = action_str.split(':', 1)
                parsed.append({
                    'action': action_type,
                    'target': action_target
                })

        return parsed

    def _validate_action(self, action_def: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a single action"""
        action = action_def.get('action', '')
        target = action_def.get('target', '')

        # Use policy engine for validation
        policy_result = self.policy_engine.evaluate({
            'action': action,
            'target': target,
            'environment': 'dry_run'
        })

        if policy_result.decision == PolicyDecision.DENY:
            return {
                'valid': False,
                'error': f"Policy denied: {'; '.join(policy_result.reasons)}"
            }

        warning = None
        if policy_result.requires_approval:
            warning = f"Action requires approval: {'; '.join(policy_result.reasons)}"

        return {
            'valid': True,
            'warning': warning
        }

    def _estimate_affected_entities(self, actions: List[Dict[str, Any]]) -> Dict[str, int]:
        """Estimate number of affected entities"""
        affected = {
            'ips': 0,
            'users': 0,
            'sessions': 0,
            'agents': 0
        }

        for action in actions:
            action_type = action.get('action', '')
            if 'ip' in action_type:
                affected['ips'] += 1
            elif 'user' in action_type:
                affected['users'] += 1
            elif 'session' in action_type:
                affected['sessions'] += 1
            elif 'agent' in action_type:
                affected['agents'] += 1

        return affected


class ValidationError(Exception):
    """Validation error"""
    pass


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Initialize components
    db_manager = DatabaseManager("postgresql://soc:soc_password@localhost:5432/soc_db")
    db_manager.create_all_tables()

    auth_manager = AuthManager(db_manager)
    crypto_signer = CryptoSigner()
    policy_engine = PolicyEngine()

    workflow = ApprovalWorkflowManager(db_manager, auth_manager, crypto_signer, policy_engine)

    # Create test user
    try:
        analyst_user = auth_manager.create_user(
            username="test_analyst",
            email="analyst@test.com",
            role=UserRole.ANALYST,
            password="test_password"
        )
    except ValueError:
        pass

    # Authenticate
    auth_context = auth_manager.authenticate_local("test_analyst", "test_password")

    # Create playbook (will default to dry-run)
    try:
        playbook = workflow.create_playbook(
            auth_context=auth_context,
            action="block_ip",
            target="192.168.1.100",
            justification="Suspicious activity detected",
            threat_type="prompt_injection",
            severity="high",
            environment="production"
        )
        print(f"Created playbook: {playbook.id} with status: {playbook.status.value}")

        # Execute dry-run
        dry_run_result = workflow.execute_dry_run(auth_context, playbook.id)
        print(f"Dry-run result: success={dry_run_result.success}, validated={len(dry_run_result.actions_validated)}")

    except (AuthorizationError, ValidationError) as e:
        print(f"Error: {e}")
