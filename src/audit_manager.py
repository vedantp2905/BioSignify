from datetime import datetime
from typing import Dict, List, Optional
import json
import hashlib
from .database.supabase_adapter import SupabaseAdapter

class AuditManager:
    def __init__(self):
        self.db = SupabaseAdapter()
        
    def add_agreement(self, agreement_id: str, recipient_email: str, embedding_reference: str,
                     created_by_user_id: str, timestamp: float) -> None:
        """Record a new agreement creation in the audit trail"""
        try:
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='created',
                actor_email=created_by_user_id,
                metadata={
                    'recipient_email': recipient_email,
                    'embedding_reference': embedding_reference,
                    'timestamp': timestamp
                }
            )
        except Exception as e:
            print(f"Error adding agreement to audit trail: {str(e)}")
            raise
        
    def add_signature(self, agreement_id: str, signature_timestamp: float, 
                     embedding_reference: str = None) -> str:
        """Record a signature event"""
        transaction_id = self._generate_transaction_id()
        
        self.db.log_audit_event(
            agreement_id=agreement_id,
            action_type='signed',
            actor_email=self.db.get_agreement(agreement_id)['recipient_email'],
            metadata={
                'transaction_id': transaction_id,
                'timestamp': signature_timestamp,
                'embedding_reference': embedding_reference
            }
        )
        return transaction_id
        
    def add_cancellation(self, agreement_id: str, cancelled_by: str, timestamp: float) -> str:
        """Record agreement cancellation"""
        transaction_id = self._generate_transaction_id()
        
        self.db.log_audit_event(
            agreement_id=agreement_id,
            action_type='cancelled',
            actor_email=cancelled_by,
            metadata={
                'transaction_id': transaction_id,
                'timestamp': timestamp
            }
        )
        return transaction_id
        
    def verify_agreement(self, agreement_id: str) -> dict:
        """Verify agreement integrity by checking audit trail"""
        audit_logs = self.db.get_agreement_audit_trail(agreement_id)
        agreement = self.db.get_agreement(agreement_id)
        
        if not agreement or not audit_logs:
            return {
                'valid': False,
                'message': 'Agreement not found or no audit trail available'
            }
            
        # Check chronological order and integrity
        creation_log = next((log for log in audit_logs if log['action_type'] == 'created'), None)
        if not creation_log:
            return {
                'valid': False,
                'message': 'Agreement creation record not found'
            }
            
        # Verify signature if agreement is signed
        if agreement['status'] == 'signed':
            signature_log = next((log for log in audit_logs if log['action_type'] == 'signed'), None)
            if not signature_log:
                return {
                    'valid': False,
                    'message': 'Agreement is marked as signed but no signature record found'
                }
                
        # Check for cancellation
        if agreement['status'] == 'cancelled':
            cancellation_log = next((log for log in audit_logs if log['action_type'] == 'cancelled'), None)
            if not cancellation_log:
                return {
                    'valid': False,
                    'message': 'Agreement is marked as cancelled but no cancellation record found'
                }
                
        return {
            'valid': True,
            'message': 'Agreement verification successful',
            'audit_trail': audit_logs
        }
        
    def _generate_transaction_id(self) -> str:
        """Generate a unique transaction ID"""
        timestamp = datetime.utcnow().timestamp()
        random_str = hashlib.sha256(str(timestamp).encode()).hexdigest()[:8]
        return f"tx_{random_str}"
