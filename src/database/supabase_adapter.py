from supabase import create_client, Client
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv
import json
from datetime import datetime
import uuid
import time
import hashlib

class SupabaseAdapter:
    def __init__(self):
        load_dotenv()
        
        # Initialize Supabase client with JWT auth
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")
        supabase_jwt = os.getenv("SUPABASE_JWT_SECRET")
        
        if not supabase_url or not supabase_key or not supabase_jwt:
            raise ValueError("Missing Supabase credentials in .env file")
            
        self.supabase: Client = create_client(
            supabase_url, 
            supabase_key
        )
        
        # Set the JWT token in the client's auth header
        self.supabase.postgrest.auth(supabase_jwt)
        

        
    def store_agreement_details(self, agreement_data: Dict) -> str:
        """Store agreement details in the database"""
        print(f"DEBUG - store_agreement_details called with data: {agreement_data}")
        current_time = datetime.utcnow().isoformat()
        
        try:
            # Check if agreement already exists
            response = self.supabase.table('agreement_details').select('*').eq('agreement_id', agreement_data['agreement_id']).execute()
            existing = response.data[0] if response.data else None
            
            # Set pdf_source based on how it was created
            pdf_source = agreement_data.get('pdf_source', 'typed')
            pdf_path = agreement_data.get('pdf_path', None)
            
            # Prepare data for insert/update - make sure column names match the database schema
            agreement_record = {
                'title': agreement_data['title'],
                'content': agreement_data.get('content', ''),
                'recipient_email': agreement_data['recipient_email'],
                'status': agreement_data.get('status', 'pending'),
                'pdf_source': pdf_source,
                'pdf_path': pdf_path,
                'updated_at': current_time
            }
            
            # Add created_by field if provided
            if 'created_by' in agreement_data and agreement_data['created_by']:
                agreement_record['created_by'] = agreement_data['created_by']
            
            # Only include embedding_reference if it exists
            if 'embedding_reference' in agreement_data and agreement_data['embedding_reference']:
                agreement_record['embedding_reference'] = agreement_data['embedding_reference']
            
            print(f"DEBUG - Final agreement record: {agreement_record}")
            
            if existing:
                print(f"DEBUG - Updating existing agreement: {agreement_data['agreement_id']}")
                response = self.supabase.table('agreement_details').update(
                    agreement_record
                ).eq('agreement_id', agreement_data['agreement_id']).execute()
            else:
                print(f"DEBUG - Creating new agreement: {agreement_data['agreement_id']}")
                agreement_record.update({
                    'agreement_id': agreement_data['agreement_id'],
                    'created_at': current_time
                })
                response = self.supabase.table('agreement_details').insert(
                    agreement_record
                ).execute()
            
            print(f"DEBUG - DB response: {response.data if hasattr(response, 'data') else 'No data'}")
            return response.data[0]['id'] if response.data else None
            
        except Exception as e:
            print(f"DEBUG - Error in store_agreement_details: {str(e)}")
            print(f"DEBUG - Error type: {type(e)}")
            import traceback
            traceback.print_exc()
            raise
        
    def get_agreement_details(self, agreement_id: str) -> Optional[Dict]:
        """Get agreement details from the database"""
        try:
            print(f"DEBUG - Fetching agreement with ID: {agreement_id}")
            # Remove .single() to avoid the error when no rows are found
            response = self.supabase.table('agreement_details').select('*').eq('agreement_id', agreement_id).execute()
            
            print(f"DEBUG - Query response: {response.data}")
            
            # If there's data, return the first row
            if response.data and len(response.data) > 0:
                return response.data[0]
            else:
                print(f"ERROR - No agreement found with ID: {agreement_id}")
                return None
            
        except Exception as e:
            print(f"ERROR - Error in get_agreement_details: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
        
    def update_agreement_status(self, agreement_id: str, status: str, signature: str = None, embedding_reference: str = None) -> None:
        """Update agreement status, signature, and embedding reference"""
        update_data = {
            'status': status,
            'updated_at': datetime.utcnow().isoformat()
        }
        
        if signature:
            update_data['signature'] = signature
            update_data['signed_at'] = datetime.utcnow().isoformat()
        
        if embedding_reference:
            update_data['embedding_reference'] = embedding_reference
        
        self.supabase.table('agreement_details') \
            .update(update_data) \
            .eq('agreement_id', agreement_id) \
            .execute()
        
    def store_pending_transaction(self, transaction: Dict) -> str:
        """Store a pending transaction in the database"""
        try:
            # Always use UTC ISO format
            timestamp = datetime.utcnow().isoformat()
            
            transaction_data = {
                'transaction_id': str(transaction['id']),
                'agreement_id': transaction['agreement_id'],
                'recipient_email': transaction['recipient_email'],
                'client_id': transaction['client_id'],
                'embedding_reference': transaction['embedding_reference'],
                'timestamp': timestamp,
                'type': transaction.get('type', 'agreement_creation')
            }
            
            response = self.supabase.table('pending_transactions').insert(transaction_data).execute()
            return response.data[0]['id'] if response.data else None
            
        except Exception as e:
            print(f"Error storing pending transaction: {str(e)}")
            raise

    def cancel_agreement(self, agreement_id: str):
        """Mark agreement as cancelled in database"""
        self.supabase.table('agreement_details').update({
            'status': 'cancelled',
            'updated_at': datetime.now().isoformat()
        }).eq('agreement_id', agreement_id).execute()

    def get_agreement(self, agreement_id: str) -> Dict:
        """Get agreement details including signature"""
        try:
            print(f"DEBUG - Fetching agreement basic info with ID: {agreement_id}")
            response = self.supabase.table('agreement_details').select(
                'agreement_id',
                'title',
                'content',
                'recipient_email',
                'status',
                'signature',
                'created_at'
            ).eq('agreement_id', agreement_id).execute()
            
            print(f"DEBUG - Get agreement response data: {response.data}")
            
            if response.data and len(response.data) > 0:
                return response.data[0]
            else:
                print(f"ERROR - No agreement found with ID: {agreement_id}")
                return None
        except Exception as e:
            print(f"ERROR - Error in get_agreement: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def log_audit_event(self, agreement_id: str, action_type: str, actor_email: str, metadata: dict = None, ip_address: str = None):
        """Log an event in the audit trail"""
        try:
            timestamp = datetime.utcnow().isoformat()
            
            # Generate a unique transaction ID if not provided in metadata
            if not metadata:
                metadata = {}
            
            transaction_id = metadata.get('transaction_id')
            if not transaction_id:
                # Generate a new transaction ID using agreement_id, action_type, and timestamp
                transaction_id_raw = f"{agreement_id}:{action_type}:{timestamp}"
                transaction_id = f"tx_{hashlib.sha256(transaction_id_raw.encode()).hexdigest()[:16]}"
                metadata['transaction_id'] = transaction_id
            
            print(f"DEBUG - Creating audit log for {action_type} on {agreement_id} with transaction ID: {transaction_id}")
            
            # Store the event in the audit logs
            response = self.supabase.table('agreement_audit_logs').insert({
                'agreement_id': agreement_id,
                'action_type': action_type,
                'actor_email': actor_email,
                'metadata': metadata,
                'ip_address': ip_address,
                'timestamp': timestamp,
                'transaction_id': transaction_id
            }).execute()
            
            if response.data:
                print(f"DEBUG - Audit log created for {action_type} on {agreement_id} with transaction ID: {transaction_id}")
                return transaction_id
            else:
                print(f"ERROR - Failed to create audit log for {action_type} on {agreement_id}. Response: {response}")
                return None
            
        except Exception as e:
            print(f"ERROR - Failed to log audit event: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def get_agreement_audit_trail(self, agreement_id: str):
        """Get the audit trail for an agreement"""
        try:
            print(f"DEBUG - Fetching audit trail for agreement: {agreement_id}")
            response = self.supabase.table('agreement_audit_logs') \
                .select('*') \
                .eq('agreement_id', agreement_id) \
                .order('timestamp', desc=False) \
                .execute()
            
            print(f"DEBUG - Retrieved {len(response.data) if response.data else 0} audit logs")
            
            if not response.data:
                # Try to create an initial log if none exist
                print(f"DEBUG - No audit logs found for {agreement_id}, creating a record event")
                
                # Get agreement details
                agreement = self.get_agreement_details(agreement_id)
                if agreement:
                    # Create a basic record event
                    import hashlib
                    from datetime import datetime
                    
                    timestamp = datetime.utcnow().isoformat()
                    transaction_id = f"tx_{hashlib.sha256(f'{agreement_id}:record:{timestamp}'.encode()).hexdigest()[:16]}"
                    
                    self.log_audit_event(
                        agreement_id=agreement_id,
                        action_type='record',
                        actor_email=agreement.get('created_by', agreement.get('recipient_email', 'system')),
                        metadata={
                            'message': 'Historical record created',
                            'status': agreement.get('status', 'unknown'),
                            'transaction_id': transaction_id,
                            'recipient_email': agreement.get('recipient_email', 'unknown')
                        }
                    )
                    
                    # Try fetching again
                    response = self.supabase.table('agreement_audit_logs') \
                        .select('*') \
                        .eq('agreement_id', agreement_id) \
                        .order('timestamp', desc=False) \
                        .execute()
                        
                    print(f"DEBUG - After creating record, retrieved {len(response.data) if response.data else 0} audit logs")
            
            return response.data or []
            
        except Exception as e:
            print(f"ERROR - Failed to get audit trail: {str(e)}")
            import traceback
            traceback.print_exc()
            return []