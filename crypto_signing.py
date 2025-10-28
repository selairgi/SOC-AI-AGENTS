"""
Cryptographic Signing for Tamper-Evident Audit Trail
Provides HMAC-based signing and verification for playbooks, approvals, and audit logs.
Implements hash chains for detecting tampering in audit logs.
"""

import hashlib
import hmac
import json
import secrets
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger("CryptoSigning")


@dataclass
class SignatureResult:
    """Result of a signing operation"""
    signature: str
    timestamp: datetime
    algorithm: str
    key_id: str


@dataclass
class VerificationResult:
    """Result of a verification operation"""
    valid: bool
    error: Optional[str] = None
    signer: Optional[str] = None
    timestamp: Optional[datetime] = None


class CryptoSigner:
    """Handles cryptographic signing and verification"""

    def __init__(self, master_key: Optional[str] = None, key_id: str = "default"):
        """
        Initialize crypto signer.

        Args:
            master_key: Master key for signing (if None, generates random)
            key_id: Identifier for this key
        """
        self.master_key = master_key or secrets.token_hex(32)
        self.key_id = key_id
        self.algorithm = "HMAC-SHA256"
        logger.info(f"Crypto signer initialized with key_id: {key_id}")

    def sign_data(self, data: Dict[str, Any], signer_id: str) -> SignatureResult:
        """
        Sign data with HMAC.

        Args:
            data: Data to sign (will be JSON serialized)
            signer_id: Identifier of the signer (user_id, system_id, etc.)

        Returns:
            SignatureResult with signature and metadata
        """
        try:
            # Create canonical representation
            canonical = self._canonicalize(data)

            # Add signing metadata
            timestamp = datetime.utcnow()
            sign_data = {
                'data': canonical,
                'signer': signer_id,
                'timestamp': timestamp.isoformat(),
                'key_id': self.key_id
            }

            # Serialize and sign
            message = json.dumps(sign_data, sort_keys=True)
            signature = hmac.new(
                self.master_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()

            logger.debug(f"Signed data for {signer_id}")

            return SignatureResult(
                signature=signature,
                timestamp=timestamp,
                algorithm=self.algorithm,
                key_id=self.key_id
            )

        except Exception as e:
            logger.error(f"Signing error: {e}")
            raise

    def verify_signature(
        self,
        data: Dict[str, Any],
        signature: str,
        signer_id: str,
        timestamp: datetime
    ) -> VerificationResult:
        """
        Verify HMAC signature.

        Args:
            data: Original data that was signed
            signature: Signature to verify
            signer_id: Expected signer identifier
            timestamp: Original signing timestamp

        Returns:
            VerificationResult
        """
        try:
            # Recreate sign data
            canonical = self._canonicalize(data)
            sign_data = {
                'data': canonical,
                'signer': signer_id,
                'timestamp': timestamp.isoformat(),
                'key_id': self.key_id
            }

            # Compute expected signature
            message = json.dumps(sign_data, sort_keys=True)
            expected_signature = hmac.new(
                self.master_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()

            # Constant-time comparison
            valid = hmac.compare_digest(signature, expected_signature)

            if valid:
                logger.debug(f"Signature verified for {signer_id}")
                return VerificationResult(
                    valid=True,
                    signer=signer_id,
                    timestamp=timestamp
                )
            else:
                logger.warning(f"Signature verification failed for {signer_id}")
                return VerificationResult(
                    valid=False,
                    error="Signature mismatch"
                )

        except Exception as e:
            logger.error(f"Verification error: {e}")
            return VerificationResult(
                valid=False,
                error=str(e)
            )

    def _canonicalize(self, data: Dict[str, Any]) -> str:
        """Create canonical representation of data"""
        # Sort keys and create deterministic JSON
        return json.dumps(data, sort_keys=True, separators=(',', ':'))


class AuditLogChain:
    """Implements hash chain for audit log integrity"""

    def __init__(self, signer: CryptoSigner):
        self.signer = signer
        self.last_hash = None
        logger.info("Audit log chain initialized")

    def create_log_entry(
        self,
        event_type: str,
        action: str,
        user_id: str,
        user_role: str,
        success: bool,
        playbook_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        target: Optional[str] = None,
        error_message: Optional[str] = None,
        before_state: Optional[Dict] = None,
        after_state: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> Tuple[Dict[str, Any], str, str]:
        """
        Create a new audit log entry with signature and hash chain.

        Returns:
            Tuple of (log_data, signature, previous_hash)
        """
        timestamp = datetime.utcnow()

        # Build log entry
        log_data = {
            'timestamp': timestamp.isoformat(),
            'event_type': event_type,
            'action': action,
            'target': target,
            'playbook_id': playbook_id,
            'alert_id': alert_id,
            'user_id': user_id,
            'user_role': user_role,
            'success': success,
            'error_message': error_message,
            'before_state': before_state,
            'after_state': after_state,
            'metadata': metadata or {},
            'previous_log_hash': self.last_hash
        }

        # Sign the entry
        sig_result = self.signer.sign_data(log_data, user_id)

        # Compute hash of this entry
        current_hash = self._compute_entry_hash(log_data, sig_result.signature)

        # Update chain
        previous_hash = self.last_hash
        self.last_hash = current_hash

        logger.debug(f"Created audit log entry: {event_type} by {user_id}")

        return log_data, sig_result.signature, previous_hash

    def _compute_entry_hash(self, log_data: Dict[str, Any], signature: str) -> str:
        """Compute hash of log entry for chain"""
        combined = json.dumps(log_data, sort_keys=True) + signature
        return hashlib.sha256(combined.encode()).hexdigest()

    def verify_chain_integrity(
        self,
        log_entries: list[Tuple[Dict[str, Any], str, Optional[str]]]
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify integrity of an audit log chain.

        Args:
            log_entries: List of (log_data, signature, previous_hash) tuples in order

        Returns:
            Tuple of (valid, error_message)
        """
        if not log_entries:
            return True, None

        expected_hash = None

        for idx, (log_data, signature, previous_hash) in enumerate(log_entries):
            # Verify hash chain
            if expected_hash is not None and previous_hash != expected_hash:
                return False, f"Hash chain broken at entry {idx}: expected {expected_hash}, got {previous_hash}"

            # Verify signature
            user_id = log_data.get('user_id')
            timestamp_str = log_data.get('timestamp')
            timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.utcnow()

            verification = self.signer.verify_signature(log_data, signature, user_id, timestamp)
            if not verification.valid:
                return False, f"Signature verification failed at entry {idx}: {verification.error}"

            # Compute hash for next entry
            expected_hash = self._compute_entry_hash(log_data, signature)

        logger.info(f"Verified chain integrity for {len(log_entries)} entries")
        return True, None


class PlaybookSigner:
    """Specialized signing for playbooks"""

    def __init__(self, signer: CryptoSigner):
        self.signer = signer

    def sign_playbook(
        self,
        playbook_id: str,
        action: str,
        target: str,
        justification: str,
        created_by: str,
        threat_type: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> SignatureResult:
        """Sign a playbook"""
        playbook_data = {
            'id': playbook_id,
            'action': action,
            'target': target,
            'justification': justification,
            'threat_type': threat_type,
            'metadata': metadata or {}
        }

        return self.signer.sign_data(playbook_data, created_by)

    def verify_playbook(
        self,
        playbook_id: str,
        action: str,
        target: str,
        justification: str,
        threat_type: Optional[str],
        metadata: Optional[Dict],
        signature: str,
        created_by: str,
        timestamp: datetime
    ) -> VerificationResult:
        """Verify playbook signature"""
        playbook_data = {
            'id': playbook_id,
            'action': action,
            'target': target,
            'justification': justification,
            'threat_type': threat_type,
            'metadata': metadata or {}
        }

        return self.signer.verify_signature(playbook_data, signature, created_by, timestamp)


class ApprovalSigner:
    """Specialized signing for approvals"""

    def __init__(self, signer: CryptoSigner):
        self.signer = signer

    def sign_approval(
        self,
        playbook_id: str,
        status: str,
        decided_by: str,
        decision_reason: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> SignatureResult:
        """Sign an approval decision"""
        approval_data = {
            'playbook_id': playbook_id,
            'status': status,
            'decision_reason': decision_reason,
            'metadata': metadata or {}
        }

        return self.signer.sign_data(approval_data, decided_by)

    def verify_approval(
        self,
        playbook_id: str,
        status: str,
        decision_reason: Optional[str],
        metadata: Optional[Dict],
        signature: str,
        decided_by: str,
        timestamp: datetime
    ) -> VerificationResult:
        """Verify approval signature"""
        approval_data = {
            'playbook_id': playbook_id,
            'status': status,
            'decision_reason': decision_reason,
            'metadata': metadata or {}
        }

        return self.signer.verify_signature(approval_data, signature, decided_by, timestamp)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Initialize signer
    signer = CryptoSigner()

    # Test playbook signing
    playbook_signer = PlaybookSigner(signer)
    sig_result = playbook_signer.sign_playbook(
        playbook_id="pb_12345",
        action="block_ip",
        target="192.168.1.100",
        justification="Critical threat detected",
        created_by="analyst_john",
        threat_type="prompt_injection"
    )
    print(f"Playbook signature: {sig_result.signature[:32]}...")

    # Verify
    verification = playbook_signer.verify_playbook(
        playbook_id="pb_12345",
        action="block_ip",
        target="192.168.1.100",
        justification="Critical threat detected",
        threat_type="prompt_injection",
        metadata={},
        signature=sig_result.signature,
        created_by="analyst_john",
        timestamp=sig_result.timestamp
    )
    print(f"Verification result: {verification.valid}")

    # Test audit log chain
    audit_chain = AuditLogChain(signer)

    # Create multiple log entries
    entries = []
    for i in range(3):
        log_data, signature, prev_hash = audit_chain.create_log_entry(
            event_type="playbook_created",
            action="block_ip",
            user_id=f"user_{i}",
            user_role="analyst",
            success=True,
            playbook_id=f"pb_{i}"
        )
        entries.append((log_data, signature, prev_hash))

    # Verify chain
    valid, error = audit_chain.verify_chain_integrity(entries)
    print(f"Chain integrity: {valid}, error: {error}")

    # Test tampering detection
    print("\nTesting tampering detection...")
    entries[1] = (
        {**entries[1][0], 'action': 'tampered'},  # Tamper with data
        entries[1][1],  # Keep original signature
        entries[1][2]
    )
    valid, error = audit_chain.verify_chain_integrity(entries)
    print(f"Chain integrity after tampering: {valid}, error: {error}")
