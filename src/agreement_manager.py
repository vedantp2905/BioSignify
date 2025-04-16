from dataclasses import dataclass
from datetime import datetime
from src.face_utils import FaceExtractor
from src.face_comparison import FaceComparer
from src.vector_store import VectorStore
import hashlib
from src.pdf_generator import AgreementPDF
from src.email_sender import EmailSender
import os
import numpy as np
import base64
from typing import Tuple, List, Optional, Dict
import time
from .audit_manager import AuditManager
from .database.supabase_adapter import SupabaseAdapter
from io import BytesIO
import shutil
from pathlib import Path

@dataclass
class Agreement:
    id: str
    title: str
    content: str
    recipient_email: str
    created_at: datetime
    face_embedding: list
    status: str = "pending"  # pending, signed, rejected
    requires_id_verification: bool = True  # New field

class AgreementManager:
    def __init__(self):
        self._db = SupabaseAdapter()
        self.audit_manager = AuditManager()
        self.face_extractor = FaceExtractor()
        self.face_comparer = FaceComparer()
        self.vector_store = VectorStore()
        self.pdf_generator = AgreementPDF()
        self.email_sender = EmailSender()
        
        # Base directory for all PDFs
        self.base_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Directory for original unsigned PDFs
        self.uploads_dir = self.base_dir / "uploads"
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        
        # Directory for signed PDFs
        self.signed_pdfs_dir = self.base_dir / "signed_agreements"
        self.signed_pdfs_dir.mkdir(parents=True, exist_ok=True)
        
    @property
    def db(self):
        return self._db
        
    def create_agreement(self, title: str, content: str, recipient_email: str, organization_id: str, created_by_user_id: str, ip_address: str = None) -> Agreement:
        """Create a new agreement with organization context"""
        agreement_id = f"agr_{int(datetime.utcnow().timestamp())}"
        timestamp = datetime.utcnow().timestamp()
        
        # Store agreement details with organization context
        self.db.store_agreement_details({
            'agreement_id': agreement_id,
            'title': title,
            'content': content,
            'recipient_email': recipient_email,
            'status': 'pending',
            'organization_id': organization_id,
            'created_by_user_id': created_by_user_id
        })
        
        # Record in audit trail with empty embedding reference for now
        self.audit_manager.add_agreement(
            agreement_id=agreement_id,
            recipient_email=recipient_email,
            embedding_reference=None,  # Add this parameter
            created_by_user_id=created_by_user_id,
            timestamp=timestamp
        )
        
        return Agreement(
            id=agreement_id,
            title=title,
            content=content,
            recipient_email=recipient_email,
            created_at=datetime.utcnow(),
            face_embedding=None
        )
    
    def verify_signature(self, agreement_id: str, verification_image_path: str, client_id: str, ip_address: str = None) -> tuple[bool, float]:
        """Verify a signature attempt using face comparison with latest client embedding"""
        try:
            # Get latest embedding for this client
            original_embedding, embedding_ref = self.vector_store.get_latest_client_embedding(client_id)
            
            # Get new face embedding
            face = self.face_extractor.extract_face(verification_image_path)
            new_embedding = self.face_extractor.get_embedding(face)
            
            # Log verification attempt with IP
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='verification_attempt',
                actor_email=client_id,
                metadata={
                    'timestamp': datetime.now().isoformat()
                },
                ip_address=ip_address
            )
            
            if original_embedding is None:
                return True, 1.0
            else:
                similarity_score, is_same_person = self.face_comparer.compare_face_embeddings(
                    original_embedding, 
                    new_embedding
                )
                return is_same_person, similarity_score
            
        except Exception as e:
            # Log error with IP
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='verification_error',
                actor_email=client_id,
                metadata={
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                },
                ip_address=ip_address
            )
            raise
    
    def create_and_send_agreement(self, title: str, content: str, recipient_email: str, 
                                client_id: str, organization_id: str) -> Agreement:
        """Create and send an agreement"""
        try:
            # Get organization details including email settings
            organization = self.db.get_organization(organization_id)
            if not organization:
                raise Exception("Organization not found")
            
            sender_email = organization.get('email')
            smtp_password = organization.get('smtp_password')
            smtp_server = organization.get('smtp_server')
            smtp_port = organization.get('smtp_port')
            
            if not sender_email or not smtp_password:
                raise Exception("Organization email settings not configured")

            # Create agreement
            agreement = self.create_agreement(
                title=title,
                content=content,
                recipient_email=recipient_email,
                organization_id=organization_id,
                created_by_user_id=client_id
            )
            
            # Generate signing URL
            base_url = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")
            signing_url = f"{base_url}/sign/{agreement.id}"
            
            # Generate PDF
            pdf_content = self.pdf_generator.generate_agreement_pdf(
                agreement_id=agreement.id,
                title=title,
                content=content,
                recipient_email=recipient_email,
                signing_url=signing_url
            )
            
            # Send email using organization's email settings
            self.email_sender.send_agreement_email(
                recipient_email=recipient_email,
                agreement_id=agreement.id,
                pdf_content=pdf_content,
                signing_url=signing_url,
                sender_email=sender_email,
                smtp_password=smtp_password,
                smtp_server=smtp_server,
                smtp_port=smtp_port
            )
            
            return agreement
            
        except Exception as e:
            print(f"Error in create_and_send_agreement: {str(e)}")
            raise

    def get_agreement_status(self, agreement_id: str) -> str:
        """Get the current status of an agreement"""
        # Get agreement from database
        agreement_data = self.db.get_agreement(agreement_id)
        
        if not agreement_data:
            return "not_found"
        
        # Check if agreement has been signed
        if agreement_data.get("signed_at"):
            return "signed"
        
        # Check if agreement has been created but not signed
        if agreement_data.get("created_at"):
            return "pending"
        
        return "unknown" 

    def process_signature(self, agreement_id: str, signature_data: Dict) -> bool:
        """Process agreement signature"""
        try:
            # Get agreement details
            agreement = self.db.get_agreement(agreement_id)
            if not agreement:
                return False
            
            if agreement['status'] != 'pending':
                return False
            
            timestamp = datetime.utcnow().timestamp()
            
            # Generate transaction ID for this signature operation
            transaction_id = f"tx_{hashlib.sha256(f'{agreement_id}:sign:{timestamp}'.encode()).hexdigest()[:16]}"
            
            # Get the latest embedding for verification
            original_embedding, embedding_ref = self.vector_store.get_latest_client_embedding(signature_data['client_id'])
            
            # Store this signature's embedding in vector store
            new_embedding_ref = f"emb_{hashlib.sha256(f'{agreement_id}:sign:{timestamp}'.encode()).hexdigest()[:16]}"
            self.vector_store.store_embedding(
                original_embedding,  # Store the verified embedding used for this signature
                signature_data['client_id'],
                agreement_id,
                verified=True
            )
            
            # Generate digital signature
            signature = hashlib.sha512(
                f"{agreement_id}:{signature_data['client_id']}:{timestamp}".encode()
            ).hexdigest()
            
            # Format signature text with proper line breaks
            signature_text = f"""Digital Signature:
{signature}

SIGNED

Agreement ID: {agreement_id}
Transaction ID: {transaction_id}
Date & Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Chicago Central Time
Signed by: {signature_data['client_id']}
[VERIFIED] Validated by facial biometrics"""

            # Generate signed PDF based on source type
            if agreement.get('pdf_source') == 'uploaded' and agreement.get('pdf_path'):
                # Use the stored PDF file
                pdf_path = agreement.get('pdf_path')
                print(f"DEBUG - Using uploaded PDF from: {pdf_path}")
                
                if os.path.exists(pdf_path):
                    with open(pdf_path, 'rb') as f:
                        original_pdf = BytesIO(f.read())
                    
                    signed_pdf = self.pdf_generator.append_signature_page(
                        original_pdf_bytes=original_pdf,
                        agreement_id=agreement_id,
                        signature_text=signature_text
                    )
                else:
                    print(f"DEBUG - PDF file not found at: {pdf_path}")
                    # Fallback to generating a new PDF if file is missing
                    signed_pdf = self.pdf_generator.generate_signed_pdf(
                        agreement_id=agreement_id,
                        title=agreement['title'],
                        content="Original PDF file was not found. This is a replacement document.",
                        recipient_email=signature_data['client_id'],
                        signature_text=signature_text
                    )
            else:
                # For drafted agreements with content
                signed_pdf = self.pdf_generator.generate_signed_pdf(
                    agreement_id=agreement_id,
                    title=agreement['title'],
                    content=agreement['content'],
                    recipient_email=signature_data['client_id'],
                    signature_text=signature_text
                )
            
            # Save the signed PDF
            signed_pdf_path = self.save_signed_pdf(agreement_id, signed_pdf)
            
            # Reset BytesIO position for email sending
            signed_pdf.seek(0)
            
            # Update agreement status with signature
            self.db.update_agreement_status(
                agreement_id=agreement_id,
                status='signed',
                signature=signature,
                signed_pdf_path=signed_pdf_path
            )
            
            # Log the signature event in audit trail with transaction ID
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='signed',
                actor_email=signature_data['client_id'],
                metadata={
                    'timestamp': timestamp,
                    'signature': signature,
                    'embedding_reference': embedding_ref,
                    'transaction_id': transaction_id,
                    'verification_status': '[VERIFIED]' if embedding_ref else 'Standard'
                },
                ip_address=signature_data.get('ip_address')
            )
            
            # Generate and send signed PDFs
            try:
                self._send_signed_pdfs(
                    agreement_id=agreement_id,
                    client_id=signature_data['client_id'],
                    signature=signature,
                    transaction_id=transaction_id
                )
            except Exception as e:
                print(f"Warning - Error sending signed PDFs: {str(e)}")
                # Continue execution - PDF sending is not critical for signature process
            
            return True
            
        except Exception as e:
            print(f"Error processing signature: {str(e)}")
            error_transaction_id = f"tx_error_{hashlib.sha256(f'{agreement_id}:error:{datetime.utcnow().timestamp()}'.encode()).hexdigest()[:16]}"
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='signature_error',
                actor_email=signature_data['client_id'],
                metadata={
                    'error': str(e),
                    'timestamp': datetime.utcnow().timestamp(),
                    'transaction_id': error_transaction_id
                },
                ip_address=signature_data.get('ip_address')
            )
            raise

    def _send_signed_pdfs(self, agreement_id: str, client_id: str, signature: str, transaction_id: str = None):
        """Generate and send signed PDFs to both parties"""
        try:
            # Get agreement details including the signed PDF path
            agreement_data = self.db.get_agreement_details(agreement_id)
            if not agreement_data:
                raise Exception("Agreement not found")
            
            # Get organization details for email settings
            organization = self.db.get_organization(agreement_data['organization_id'])
            if not organization:
                raise Exception("Organization not found")
            
            # Get SMTP settings
            smtp_password = organization.get('smtp_password')
            smtp_server = organization.get('smtp_server')
            smtp_port = organization.get('smtp_port')
            sender_email = organization.get('email')
            
            if not smtp_password or not smtp_server or not smtp_port or not sender_email:
                raise Exception("Organization email settings not configured")

            # Read the saved signed PDF
            signed_pdf_path = agreement_data.get('signed_pdf_path')
            if not signed_pdf_path or not os.path.exists(signed_pdf_path):
                raise Exception("Signed PDF not found")
            
            with open(signed_pdf_path, 'rb') as f:
                signed_pdf = BytesIO(f.read())
            
            # Format signature text with proper line breaks
            signature_text = f"""Digital Signature:
{signature}

SIGNED

Agreement ID: {agreement_id}
Transaction ID: {transaction_id or 'N/A'}
Date & Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Chicago Central Time
Signed by: {client_id}
[VERIFIED] Validated by facial biometrics"""
            
            # Generate signed PDF based on source type
            if agreement_data.get('pdf_source') == 'uploaded' and agreement_data.get('pdf_path'):
                # Use the stored PDF file
                pdf_path = agreement_data.get('pdf_path')
                print(f"DEBUG - Using uploaded PDF from: {pdf_path}")
                
                if os.path.exists(pdf_path):
                    with open(pdf_path, 'rb') as f:
                        original_pdf = BytesIO(f.read())
                    
                    signed_pdf = self.pdf_generator.append_signature_page(
                        original_pdf_bytes=original_pdf,
                        agreement_id=agreement_id,
                        signature_text=signature_text
                    )
                else:
                    print(f"DEBUG - PDF file not found at: {pdf_path}")
                    # Fallback to generating a new PDF if file is missing
                    signed_pdf = self.pdf_generator.generate_signed_pdf(
                        agreement_id=agreement_id,
                        title=agreement_data['title'],
                        content="Original PDF file was not found. This is a replacement document.",
                        recipient_email=client_id,
                        signature_text=signature_text
                    )
            else:
                # For drafted agreements with content
                signed_pdf = self.pdf_generator.generate_signed_pdf(
                    agreement_id=agreement_id,
                    title=agreement_data['title'],
                    content=agreement_data['content'],
                    recipient_email=client_id,
                    signature_text=signature_text
                )
            
            # Configure email sender with organization SMTP settings
            self.email_sender.configure_smtp(
                smtp_server=smtp_server,
                smtp_port=smtp_port,
                smtp_password=smtp_password
            )
            
            # Send to signer (client)
            self.email_sender.send_signed_agreement_email(
                recipient_email=client_id,
                agreement_id=agreement_id,
                pdf_content=signed_pdf,
                signature=signature,
                transaction_id=transaction_id,
                sender_email=sender_email
            )
            
            # Send to creator
            creator_email = agreement_data.get('created_by', agreement_data.get('sender_email'))
            if creator_email and creator_email != client_id:
                signed_pdf.seek(0)  # Reset buffer position
                self.email_sender.send_signed_agreement_email(
                    recipient_email=creator_email,
                    agreement_id=agreement_id,
                    pdf_content=signed_pdf,
                    signature=signature,
                    transaction_id=transaction_id,
                    sender_email=sender_email
                )
            
            # Log PDF sent event
            pdf_sent_transaction_id = f"tx_{hashlib.sha256(f'{agreement_id}:pdf_sent:{datetime.utcnow().timestamp()}'.encode()).hexdigest()[:16]}"
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='pdf_sent',
                actor_email=client_id,
                metadata={
                    'timestamp': datetime.utcnow().timestamp(),
                    'sent_to': [client_id, creator_email] if creator_email and creator_email != client_id else [client_id],
                    'transaction_id': pdf_sent_transaction_id,
                    'parent_transaction_id': transaction_id
                },
                ip_address=None
            )
            
        except Exception as e:
            print(f"Error sending signed PDFs: {str(e)}")
            raise

    def cancel_agreement(self, agreement_id: str, client_id: str, ip_address: str = None) -> Tuple[bool, str]:
        """Cancel an agreement"""
        agreement = self.db.get_agreement(agreement_id)
        if not agreement:
            return False, "Agreement not found"
            
        if agreement['status'] != 'pending':
            return False, f"Agreement is already {agreement['status']}"
            
        timestamp = datetime.utcnow().timestamp()
        
        # Record cancellation in audit trail
        transaction_id = self.audit_manager.add_cancellation(
            agreement_id=agreement_id,
            cancelled_by=client_id,
            timestamp=timestamp
        )
        
        # Update agreement status
        self.db.update_agreement_status(
            agreement_id=agreement_id,
            status='cancelled'
        )
        
        return True, "Agreement cancelled successfully"

    def verify_agreement(self, agreement_id: str) -> dict:
        """Verify agreement integrity"""
        return self.audit_manager.verify_agreement(agreement_id)

    def generate_signature(self, face_embedding: np.ndarray, agreement_id: str, client_id: str, timestamp: float) -> str:
        """Generate a cryptographic signature from face embedding and metadata"""
        # Convert embedding to bytes and hash it
        embedding_bytes = face_embedding.tobytes()
        embedding_hash = hashlib.sha512(embedding_bytes).hexdigest()
        
        # Combine all elements
        signature_data = f"{embedding_hash}:{agreement_id}:{client_id}:{timestamp}"
        
        # Create final signature hash
        signature = hashlib.sha512(signature_data.encode()).hexdigest()
        return signature

    def create_agreement_from_pdf(self, title: str, recipient_email: str, pdf_file, client_id: str, sender_email: str, ip_address: str = None) -> Agreement:
        """Create a new agreement from an uploaded PDF file"""
        try:
            # Get organization details for email settings
            organization = self.db.get_organization_by_email(sender_email)
            if not organization:
                raise Exception("Organization not found for sender email")
            
            # Get organization ID and SMTP settings
            organization_id = organization['id']
            smtp_password = organization.get('smtp_password')
            smtp_server = organization.get('smtp_server')
            smtp_port = organization.get('smtp_port')
            
            if not smtp_password or not smtp_server or not smtp_port:
                raise Exception("Organization email settings not configured")

            # Create unique ID for agreement
            agreement_id = f"agr_{int(datetime.utcnow().timestamp())}"
            
            # Create organization-specific subdirectory for original PDFs
            org_uploads_dir = self.uploads_dir / organization_id
            org_uploads_dir.mkdir(parents=True, exist_ok=True)

            # Create file path for storing the original PDF
            pdf_filename = f"original_{agreement_id}.pdf"
            pdf_path = org_uploads_dir / pdf_filename

            print(f"DEBUG - Saving original PDF to: {pdf_path}")

            # Handle different types of input and save to file
            if isinstance(pdf_file, BytesIO):
                pdf_file.seek(0)
                pdf_path.write_bytes(pdf_file.read())
            elif hasattr(pdf_file, 'read') and hasattr(pdf_file, 'save'):
                pdf_file.save(pdf_path)
            elif hasattr(pdf_file, 'read'):
                pdf_path.write_bytes(pdf_file.read())
            elif isinstance(pdf_file, bytes):
                pdf_path.write_bytes(pdf_file)
            else:
                raise ValueError(f"Unsupported PDF file type: {type(pdf_file)}")
            
            print(f"DEBUG - PDF saved successfully to: {pdf_path}")
            
            # Store agreement details with pdf_source and pdf_path (convert path to string)
            stored_id = self.db.store_agreement_details({
                'agreement_id': agreement_id,
                'title': title,
                'content': '',  # Empty string for uploaded PDFs
                'recipient_email': recipient_email,
                'status': 'pending',
                'created_by': client_id,
                'pdf_source': 'uploaded',
                'pdf_path': str(pdf_path),  # Convert WindowsPath to string
                'organization_id': organization_id
            })
            
            if not stored_id:
                raise Exception("Failed to store agreement details in database")
            
            # Generate signing URL
            base_url = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")
            signing_url = f"{base_url}/sign/{agreement_id}"
            
            # Send email with sender_email
            self.email_sender.send_agreement_email(
                recipient_email=recipient_email,
                agreement_id=agreement_id,
                pdf_content=pdf_file,
                signing_url=signing_url,
                sender_email=sender_email,
                smtp_password=smtp_password,
                smtp_server=smtp_server,
                smtp_port=smtp_port
            )
            
            # Log agreement creation in audit trail
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='created',
                actor_email=client_id,
                metadata={
                    'title': title,
                    'recipient_email': recipient_email,
                    'type': 'pdf_upload',
                    'timestamp': round(time.time(), 6)
                },
                ip_address=ip_address
            )
            
            return Agreement(
                id=agreement_id,
                title=title,
                content='',
                recipient_email=recipient_email,
                created_at=datetime.now(),
                face_embedding=None,
                status="pending"
            )
            
        except Exception as e:
            print(f"Error creating agreement from PDF: {str(e)}")
            # Log the exception type and traceback for debugging
            import traceback
            print(f"Exception type: {type(e).__name__}")
            traceback.print_exc()
            raise

    def verify_id_and_face(self, agreement_id: str, id_image: str, selfie_image: str, client_id: str, ip_address: str = None) -> Tuple[bool, str]:
        """Verify government ID and match face with live selfie"""
        try:
            # Decode base64 images
            id_bytes = base64.b64decode(id_image.split(',')[1])
            selfie_bytes = base64.b64decode(selfie_image.split(',')[1])
            
            # Extract face from ID
            id_face = self.face_extractor.extract_face_from_bytes(id_bytes)
            if id_face is None:
                return False, "No face detected in ID"
            
            # Extract face from selfie
            selfie_face = self.face_extractor.extract_face_from_bytes(selfie_bytes)
            if selfie_face is None:
                return False, "No face detected in selfie"
            
            # Get embeddings
            id_embedding = self.face_extractor.get_embedding(id_face)
            selfie_embedding = self.face_extractor.get_embedding(selfie_face)
            
            # Compare faces
            similarity_score, is_same_person = self.face_comparer.compare_face_embeddings(
                id_embedding,
                selfie_embedding
            )
            
            # Log verification attempt
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='id_verification_attempt',
                actor_email=client_id,
                metadata={
                    'success': str(similarity_score >= 0.50),
                    'similarity_score': float(similarity_score),
                    'timestamp': datetime.now().isoformat()
                },
                ip_address=ip_address
            )
            
            if similarity_score < 0.50:
                return False, f"ID verification failed. Face mismatch (similarity: {similarity_score:.2f})"
            
            # Store verified embedding for future use
            embedding_ref = self.vector_store.store_embedding(
                selfie_embedding,
                client_id,
                agreement_id,
                verified=True
            )
            
            # Return success without signing
            return True, "Identity verified successfully. Please proceed with signing."
            
        except Exception as e:
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='id_verification_error',
                actor_email=client_id,
                metadata={
                    'error_type': e.__class__.__name__,
                    'error_message': str(e)
                },
                ip_address=ip_address
            )
            raise

    def save_signed_pdf(self, agreement_id: str, pdf_content: BytesIO) -> str:
        """Save signed PDF to the signed agreements directory"""
        try:
            # Get agreement details
            agreement = self.db.get_agreement_details(agreement_id)
            if not agreement:
                raise ValueError(f"Agreement not found: {agreement_id}")
                
            # Create organization-specific subdirectory for signed PDFs
            org_id = agreement.get('organization_id')
            org_signed_dir = self.signed_pdfs_dir / org_id
            org_signed_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"signed_{agreement_id}_{timestamp}.pdf"
            filepath = org_signed_dir / filename
            
            # Convert BytesIO to bytes and save
            if isinstance(pdf_content, BytesIO):
                pdf_content.seek(0)
                filepath.write_bytes(pdf_content.read())
            else:
                filepath.write_bytes(pdf_content)
                
            # Convert path to string using absolute path
            filepath_str = str(filepath.absolute())
            
            # Update agreement record with signed PDF path
            self.db.update_agreement_status(
                agreement_id=agreement_id,
                status='signed',
                signed_pdf_path=filepath_str
            )
            
            return filepath_str
            
        except Exception as e:
            print(f"Error saving signed PDF: {str(e)}")
            raise

    def get_signed_pdf(self, agreement_id: str) -> Optional[bytes]:
        """Retrieve signed PDF content"""
        try:
            agreement = self.db.get_agreement_details(agreement_id)
            if not agreement or not agreement.get('signed_pdf_path'):
                return None
                
            filepath = agreement['signed_pdf_path']
            if not os.path.exists(filepath):
                print(f"Warning: Signed PDF file not found at {filepath}")
                return None
                
            with open(filepath, 'rb') as f:
                return f.read()
                
        except Exception as e:
            print(f"Error retrieving signed PDF: {str(e)}")
            return None