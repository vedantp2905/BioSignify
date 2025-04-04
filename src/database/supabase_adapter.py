from supabase import create_client, Client
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv
import json
from datetime import datetime
import uuid
import time

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
        
    def store_block(self, block_data: Dict) -> str:
        """Store a block in the database"""
        try:
            # Convert numeric timestamp to datetime
            timestamp = datetime.utcfromtimestamp(block_data['timestamp']).isoformat()
            
            response = self.supabase.table('blocks').insert({
                'index': block_data['index'],
                'timestamp': timestamp,  # Now ISO string
                'transactions': json.dumps(block_data['transactions']),
                'previous_hash': block_data['previous_hash'],
                'nonce': block_data['nonce'],
                'hash': block_data['hash']
            }).execute()
            
            return response.data[0]['id'] if response.data else None
            
        except Exception as e:
            print(f"Error storing block: {str(e)}")
            print(f"Block data: {block_data}")
            raise
        
    def get_blocks(self):
        """Get all blocks from the database"""
        try:
            response = self.supabase.table('blocks').select('*').order('index').execute()
            blocks = response.data if response.data else []
            
            # Process each block
            for block in blocks:
                # Parse transactions JSON string
                if 'transactions' in block and isinstance(block['transactions'], str):
                    block['transactions'] = json.loads(block['transactions'])
                
                # Convert ISO timestamp to Unix timestamp
                if 'timestamp' in block and isinstance(block['timestamp'], str):
                    try:
                        dt = datetime.fromisoformat(block['timestamp'].replace('Z', '+00:00'))
                        block['timestamp'] = dt.timestamp()
                    except (ValueError, TypeError):
                        block['timestamp'] = time.time()
                        
            return blocks
        except Exception as e:
            print(f"Error getting blocks: {str(e)}")
            return []
        
    def get_latest_block(self) -> Optional[Dict]:
        """Get the most recent block"""
        response = self.supabase.table('blocks').select('*').order('index', desc=True).limit(1).execute()
        
        if response.data:
            block = response.data[0]
            # Parse ISO timestamp string to datetime, then to timestamp float
            timestamp = datetime.fromisoformat(block['timestamp']).timestamp()
            return {
                'index': block['index'],
                'timestamp': timestamp,
                'transactions': json.loads(block['transactions']),
                'previous_hash': block['previous_hash'],
                'nonce': block['nonce'],
                'hash': block['hash']
            }
        return None

    def get_pending_transactions(self) -> List[Dict]:
        """Get all pending transactions"""
        try:
            response = self.supabase.table('pending_transactions').select('*').execute()
            return response.data if response.data else []
        except Exception as e:
            print(f"Error getting pending transactions: {str(e)}")
            return []
        
    def clear_pending_transactions(self):
        """Clear all pending transactions after mining"""
        # Delete all pending transactions using a true condition
        self.supabase.table('pending_transactions').delete().gte('created_at', '2000-01-01').execute()
        
    def store_agreement_details(self, agreement_data: Dict) -> str:
        """Store agreement details in the database"""
        current_time = datetime.utcnow().isoformat()
        
        try:
            # Check if agreement already exists
            response = self.supabase.table('agreement_details').select('*').eq('agreement_id', agreement_data['agreement_id']).execute()
            existing = response.data[0] if response.data else None
            
            # Prepare data for insert/update
            agreement_record = {
                'title': agreement_data['title'],
                'content': agreement_data.get('content'),
                'recipient_email': agreement_data['recipient_email'],
                'status': agreement_data.get('status', 'pending'),
                'pdf_path': agreement_data.get('pdf_path'),
                'updated_at': current_time
            }
            
            if existing:
                response = self.supabase.table('agreement_details').update(
                    agreement_record
                ).eq('agreement_id', agreement_data['agreement_id']).execute()
            else:
                agreement_record.update({
                    'agreement_id': agreement_data['agreement_id'],
                    'created_at': current_time
                })
                response = self.supabase.table('agreement_details').insert(
                    agreement_record
                ).execute()
            
            return response.data[0]['id'] if response.data else None
            
        except Exception as e:
            print(f"Error in store_agreement_details: {str(e)}")
            raise
        
    def get_agreement_details(self, agreement_id: str) -> Optional[Dict]:
        """Get agreement details from the database"""
        response = self.supabase.table('agreement_details').select('*').eq('agreement_id', agreement_id).single().execute()
        return response.data if response.data else None
        
    def update_agreement_status(self, agreement_id: str, status: str, signature: str = None):
        """Update agreement status and signature in database"""
        update_data = {
            'status': status,
            'updated_at': datetime.now().isoformat()
        }
        if signature:
            update_data['signature'] = signature
        
        self.supabase.table('agreement_details').update(update_data).eq('agreement_id', agreement_id).execute()
        
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
        response = self.supabase.table('agreement_details').select(
            'agreement_id',
            'title',
            'content',
            'recipient_email',
            'status',
            'signature',
            'created_at'
        ).eq('agreement_id', agreement_id).execute()
        
        if response.data:
            return response.data[0]
        return None

    def log_audit_event(self, agreement_id: str, action_type: str, actor_email: str, metadata: dict, ip_address: str = None):
        """Log an audit event with IP address"""
        try:
            # Ensure metadata is a dict
            if not isinstance(metadata, dict):
                metadata = {'data': str(metadata)}
            
            # Create a copy of metadata to avoid modifying the original
            event_metadata = metadata.copy()
            
            # Add IP address to metadata if provided
            if ip_address:
                event_metadata['ip_address'] = ip_address
            
            # Always use UTC timestamp
            current_time = datetime.utcnow().isoformat()
            
            # Add timestamp to metadata
            event_metadata['timestamp'] = current_time
            
            # Create audit log entry with consistent UTC timestamp
            response = self.supabase.table('agreement_audit_logs').insert({
                'agreement_id': agreement_id,
                'action_type': action_type,
                'actor_email': actor_email,
                'metadata': event_metadata,
                'ip_address': ip_address,
                'timestamp': current_time  # Use same UTC timestamp
            }).execute()
            
            return response.data[0] if response.data else None
            
        except Exception as e:
            print(f"DEBUG - Error in log_audit_event: {str(e)}")
            return None

    def get_agreement_audit_trail(self, agreement_id: str) -> List[Dict]:
        """Get all audit logs for an agreement ordered by timestamp"""
        try:
            response = self.supabase.table('agreement_audit_logs')\
                .select('*')\
                .eq('agreement_id', agreement_id)\
                .order('timestamp')\
                .execute()
            
            return response.data if response.data else []
        except Exception as e:
            print(f"Error getting audit trail: {str(e)}")
            return []