import traceback
from supabase import create_client, Client
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv
import json
from datetime import datetime, timedelta
import uuid
import time
import hashlib
import secrets
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

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
        
        # Initialize encryption
        try:
            encryption_key = os.getenv("AES_ENCRYPTION_KEY")
            if not encryption_key:
                print("Warning: AES_ENCRYPTION_KEY not found, running without encryption")
                self.cipher_suite = None
            else:
                # Generate Fernet key from encryption key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'biosignify_salt',
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
                self.cipher_suite = Fernet(key)
        except Exception as e:
            print(f"Warning: Failed to initialize encryption: {str(e)}")
            self.cipher_suite = None

    def encrypt_smtp_password(self, password: str) -> str:
        """Encrypt SMTP password"""
        try:
            if not password:
                return None
            if not self.cipher_suite:
                print("Warning: Encryption not initialized, storing password unencrypted")
                return password
            return self.cipher_suite.encrypt(password.encode()).decode()
        except Exception as e:
            print(f"Error encrypting password: {str(e)}")
            return password

    def decrypt_smtp_password(self, encrypted_password: str) -> str:
        """Decrypt SMTP password"""
        try:
            if not encrypted_password:
                return None
            if not self.cipher_suite:
                print("Warning: Encryption not initialized, returning password as-is")
                return encrypted_password
            return self.cipher_suite.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            print(f"Error decrypting password: {str(e)}")
            return encrypted_password

    def store_agreement_details(self, agreement_data: Dict) -> str:
        """Store agreement details in the database"""
        print(f"DEBUG - store_agreement_details called with data: {agreement_data}")
        print(f"DEBUG - Organization ID: {agreement_data.get('organization_id')}")
        current_time = datetime.utcnow().isoformat()
        
        try:
            # Check if agreement already exists
            response = self.supabase.table('agreement_details').select('*').eq('agreement_id', agreement_data['agreement_id']).execute()
            existing = response.data[0] if response.data else None
            
            # Set pdf_source and paths
            pdf_source = agreement_data.get('pdf_source', 'typed')
            pdf_path = agreement_data.get('pdf_path', None)
            signed_pdf_path = agreement_data.get('signed_pdf_path', None)  # New field
            
            # Prepare data for insert/update - make sure column names match the database schema
            agreement_record = {
                'title': agreement_data['title'],
                'content': agreement_data.get('content', ''),
                'recipient_email': agreement_data['recipient_email'],
                'status': agreement_data.get('status', 'pending'),
                'pdf_source': pdf_source,
                'pdf_path': pdf_path,
                'signed_pdf_path': signed_pdf_path,  # Add signed PDF path
                'organization_id': agreement_data.get('organization_id'),
                'created_by': agreement_data.get('created_by'),
                'updated_at': current_time
            }
            
            # Only include embedding_reference if it exists
            if 'embedding_reference' in agreement_data and agreement_data['embedding_reference']:
                agreement_record['embedding_reference'] = agreement_data['embedding_reference']
            
            # Only include signature if it exists
            if 'signature' in agreement_data and agreement_data['signature']:
                agreement_record['signature'] = agreement_data['signature']
                agreement_record['signed_at'] = current_time
            
            print(f"DEBUG - Final agreement record: {agreement_record}")
            
            if existing:
                print(f"DEBUG - Updating existing agreement: {agreement_data['agreement_id']}")
                # Update existing record
                response = self.supabase.table('agreement_details').update(
                    agreement_record
                ).eq('agreement_id', agreement_data['agreement_id']).execute()
            else:
                print(f"DEBUG - Creating new agreement: {agreement_data['agreement_id']}")
                # Create new record
                agreement_record['agreement_id'] = agreement_data['agreement_id']
                agreement_record['created_at'] = current_time
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
        
    def update_agreement_status(self, agreement_id: str, status: str, signature: str = None, embedding_reference: str = None, signed_pdf_path: str = None) -> None:
        """Update agreement status, signature, embedding reference, and signed PDF path"""
        update_data = {
            'status': status,
            'updated_at': datetime.utcnow().isoformat()
        }
        
        if signature:
            update_data['signature'] = signature
            update_data['signed_at'] = datetime.utcnow().isoformat()
        
        if embedding_reference:
            update_data['embedding_reference'] = embedding_reference
        
        if signed_pdf_path:
            update_data['signed_pdf_path'] = signed_pdf_path
        
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
                '*'  # Select all fields instead of specific ones
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

    def create_organization(self, name: str, email: str) -> dict:
        """Create a new organization"""
        try:
            response = self.supabase.table('organizations').insert({
                'name': name,
                'email': email
            }).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            print(f"Error creating organization: {str(e)}")
            raise

    def add_organization_user(self, organization_id: str, email: str, role: str = 'user', password_hash: str = None, status: str = 'pending') -> dict:
        """Add a user to an organization with optional password and status"""
        try:
            user_data = {
                'organization_id': organization_id,
                'email': email,
                'role': role,
                'status': status
            }
            
            # Add password hash if provided
            if password_hash:
                user_data['password_hash'] = password_hash

            response = self.supabase.table('organization_users').insert(user_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            print(f"Error adding organization user: {str(e)}")
            raise

    def verify_user_credentials(self, email: str, password_hash: str) -> dict:
        """Verify user credentials and return user data if valid"""
        try:
            # Get user with matching email and password hash
            response = self.supabase.table('organization_users')\
                .select('*')\
                .eq('email', email)\
                .eq('password_hash', password_hash)\
                .execute()

            if not response.data:
                return None

            user = response.data[0]
            
            # Get organization details
            org_response = self.supabase.table('organizations')\
                .select('*')\
                .eq('id', user['organization_id'])\
                .execute()

            if not org_response.data:
                return None

            # Return combined user and organization data
            return {
                'email': user['email'],
                'role': user['role'],
                'organization_id': user['organization_id'],
                'organization_name': org_response.data[0]['name']
            }

        except Exception as e:
            print(f"Error verifying user credentials: {str(e)}")
            return None

    def update_user_password(self, email: str, new_password_hash: str) -> bool:
        """Update user's password"""
        try:
            response = self.supabase.table('organization_users')\
                .update({'password_hash': new_password_hash})\
                .eq('email', email)\
                .execute()
            return bool(response.data)
        except Exception as e:
            print(f"Error updating user password: {str(e)}")
            return False

    def get_user_by_email(self, email: str) -> dict:
        """Get user details by email"""
        try:
            response = self.supabase.table('organization_users')\
                .select('*')\
                .eq('email', email)\
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            print(f"Error getting user by email: {str(e)}")
            return None

    def get_user_organizations(self, email: str) -> list:
        """Get all organizations a user belongs to"""
        try:
            response = self.supabase.table('organization_users')\
                .select('organizations(*)')\
                .eq('email', email)\
                .execute()
            return response.data
        except Exception as e:
            print(f"Error getting user organizations: {str(e)}")
            raise

    def get_organization_agreements(self, organization_id: str, status: str = None) -> list:
        """Get all agreements for an organization"""
        try:
            query = self.supabase.table('agreement_details')\
                .select('*')\
                .eq('organization_id', organization_id)
                
            if status:
                query = query.eq('status', status)
                
            # Order by created_at in descending order (newest first)
            query = query.order('created_at', desc=True)
            
            response = query.execute()
            
            print(f"DEBUG - Retrieved {len(response.data) if response.data else 0} agreements for organization {organization_id}")
            print(f"DEBUG - First agreement data: {response.data[0] if response.data else None}")
            
            return response.data or []
        except Exception as e:
            print(f"Error getting organization agreements: {str(e)}")
            traceback.print_exc()
            return []

    def get_organization(self, org_id: str) -> dict:
        """Get organization details with decrypted SMTP password"""
        try:
            print(f"DEBUG - Fetching organization with ID: {org_id}")
            response = self.supabase.table('organizations')\
                .select('*')\
                .eq('id', org_id)\
                .execute()
                
            if not response.data:
                print(f"DEBUG - No organization found with ID: {org_id}")
                return None
                
            org_data = response.data[0]
            
            # Handle SMTP password decryption
            if org_data and org_data.get('smtp_password'):
                try:
                    org_data['smtp_password'] = self.decrypt_smtp_password(org_data['smtp_password'])
                except Exception as e:
                    print(f"Warning: Failed to decrypt SMTP password: {str(e)}")
                    # Keep the encrypted password rather than failing
                    pass
                
            return org_data
            
        except Exception as e:
            print(f"Error getting organization: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def get_organization_users(self, organization_id: str) -> list:
        """Get all users for an organization"""
        try:
            response = self.supabase.table('organization_users') \
                .select('*') \
                .eq('organization_id', organization_id) \
                .execute()
            
            return response.data
            
        except Exception as e:
            print(f"Error getting organization users: {str(e)}")
            return []

    def update_organization(self, org_id: str, data: dict) -> dict:
        """Update organization details"""
        try:
            response = self.supabase.table('organizations')\
                .update(data)\
                .eq('id', org_id)\
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            print(f"Error updating organization: {str(e)}")
            raise

    def create_invitation_token(self, email: str, organization_id: str, token: str) -> str:
        """Create an invitation token for a new user"""
        try:
            print(f"DEBUG - Creating invitation token for {email} in org {organization_id}")
            expiry = datetime.utcnow() + timedelta(days=7)
            
            # Create the invitation record
            invitation_data = {
                'email': email,
                'organization_id': organization_id,
                'token': token,
                'expires_at': expiry.isoformat()
            }
            
            print(f"DEBUG - Invitation data: {invitation_data}")
            
            response = self.supabase.table('user_invitations').insert(invitation_data).execute()
            
            print(f"DEBUG - Supabase response: {response.data if hasattr(response, 'data') else 'No data'}")
            
            if not response.data:
                print("DEBUG - No data returned from invitation token creation")
                return None
            
            return token
            
        except Exception as e:
            print(f"Error creating invitation token: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def verify_invitation_token(self, token: str) -> dict:
        """Verify an invitation token"""
        try:
            print(f"Verifying token: {token}")  # Debug log
            
            # Get the invitation
            response = self.supabase.table('user_invitations') \
                .select('*') \
                .eq('token', token) \
                .execute()
                
            print(f"Query response: {response.data}")  # Debug log
            
            if not response.data:
                print("No invitation found with this token")  # Debug log
                return None
                
            # Return the first invitation found
            return response.data[0]
            
        except Exception as e:
            print(f"Error verifying invitation token: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def complete_user_setup(self, token: str, password_hash: str) -> bool:
        """Complete user setup from invitation token"""
        try:
            print(f"Starting complete_user_setup with token: {token}")
            
            # First get the invitation
            invitation = self.verify_invitation_token(token)
            if not invitation:
                print("Failed to verify invitation token")
                return False
                
            email = invitation['email']
            organization_id = invitation['organization_id']
            print(f"Found invitation for email: {email}")
            
            # First check if user exists
            user_response = self.supabase.table('organization_users') \
                .select('*') \
                .eq('email', email) \
                .execute()
                
            if not user_response.data:
                # Create new user if doesn't exist
                print(f"Creating new user record for {email}")
                create_response = self.supabase.table('organization_users') \
                    .insert({
                        'email': email,
                        'organization_id': organization_id,
                        'password_hash': password_hash,
                        'status': 'active',
                        'role': 'user'
                    }) \
                    .execute()
                    
                if not create_response.data:
                    print("Failed to create user record")
                    return False
            else:
                # Update existing user
                print(f"Updating existing user record for {email}")
                update_response = self.supabase.table('organization_users') \
                    .update({
                        'status': 'active',
                        'password_hash': password_hash
                    }) \
                    .eq('email', email) \
                    .execute()
                    
                if not update_response.data:
                    print("Failed to update user record")
                    return False
            
            # Delete the used invitation token
            delete_response = self.supabase.table('user_invitations') \
                .delete() \
                .eq('token', token) \
                .execute()
                
            print(f"Token deletion response: {delete_response.data}")
            
            return True
            
        except Exception as e:
            print(f"Error completing user setup: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def delete_organization_user(self, user_id: str) -> bool:
        """Delete a user from an organization"""
        try:
            response = self.supabase.table('organization_users')\
                .delete()\
                .eq('id', user_id)\
                .execute()
            return bool(response.data)
        except Exception as e:
            print(f"Error deleting organization user: {str(e)}")
            return False

    def update_organization_email_settings(self, org_id: str, email_settings: dict) -> dict:
        """Update organization email settings with encrypted SMTP password"""
        try:
            # Encrypt SMTP password if provided
            if 'smtp_password' in email_settings:
                email_settings['smtp_password'] = self.encrypt_smtp_password(email_settings['smtp_password'])
            
            response = self.supabase.table('organizations')\
                .update(email_settings)\
                .eq('id', org_id)\
                .execute()
            
            return response.data[0] if response.data else None
        except Exception as e:
            print(f"Error updating organization email settings: {str(e)}")
            raise

    def get_organization_by_email(self, email: str) -> dict:
        """Get organization details by email address with decrypted SMTP password"""
        result = self.supabase.table('organizations').select('*').eq('email', email).execute()
        if result.data:
            if result.data[0].get('smtp_password'):
                result.data[0]['smtp_password'] = self.decrypt_smtp_password(result.data[0]['smtp_password'])
            return result.data[0]
        return None

    def delete_invitation_token(self, token: str) -> bool:
        """Delete an invitation token"""
        try:
            response = self.supabase.table('user_invitations')\
                .delete()\
                .eq('token', token)\
                .execute()
            return bool(response.data)
        except Exception as e:
            print(f"Error deleting invitation token: {str(e)}")
            return False

    def remove_organization_user(self, organization_id: str, email: str) -> bool:
        """Remove a user from an organization"""
        try:
            response = self.supabase.table('organization_users') \
                .delete() \
                .eq('organization_id', organization_id) \
                .eq('email', email) \
                .execute()
            
            return bool(response.data)
            
        except Exception as e:
            print(f"Error removing organization user: {str(e)}")
            return False