from dataclasses import dataclass
from datetime import datetime
from src.blockchain import AgreementBlockchain, StorageType
from src.face_utils import FaceExtractor
from src.face_comparison import FaceComparer
from src.vector_store import VectorStore
import hashlib
from src.pdf_generator import AgreementPDF
from src.email_sender import EmailSender
import os
import numpy as np
import base64
from typing import Tuple
import time

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
    def __init__(self, blockchain_path: str = "data/blockchain.json"):
        # Use database storage
        self.blockchain = AgreementBlockchain(storage_type=StorageType.DATABASE)
        self.face_extractor = FaceExtractor()
        self.face_comparer = FaceComparer()
        self.vector_store = VectorStore()
        self.pdf_generator = AgreementPDF()
        self.email_sender = EmailSender()
        
    @property
    def db(self):
        return self.blockchain.db
        
    def create_agreement(self, title: str, content: str, recipient_email: str, client_id: str, ip_address: str = None) -> Agreement:
        """Create a new agreement with audit logging"""
        try:
            # Generate single timestamp with consistent precision
            current_time = round(time.time(), 6)  # Round to microseconds
            
            agreement_data = f"{title}{content}{recipient_email}{current_time}"
            agreement_id = hashlib.sha512(agreement_data.encode()).hexdigest()[:16]

            # Store reference in blockchain with same timestamp
            transaction_id = self.blockchain.add_agreement(
                agreement_id=agreement_id,
                recipient_email=recipient_email,
                embedding_reference=None,
                client_id=client_id,
                timestamp=current_time  # Pass the same timestamp
            )
            
            # Mine the block and ensure it's stored
            block = self.blockchain.mine_pending_transactions()
            if not block:
                raise Exception("Failed to mine block for agreement")
            
            # Store agreement details in database
            self.db.store_agreement_details({
                'agreement_id': agreement_id,
                'title': title,
                'content': content,
                'recipient_email': recipient_email,
                'status': 'pending'
            })
            
            # Generate and send PDF
            signing_url = f"{os.getenv('SIGNING_BASE_URL', 'http://localhost:5000')}/sign/{agreement_id}"
            pdf_path = self.pdf_generator.generate_agreement_pdf(
                agreement_id=agreement_id,
                title=title,
                content=content,
                recipient_email=recipient_email,
                signing_url=signing_url
            )
            
            try:
                self.email_sender.send_agreement_email(
                    recipient_email=recipient_email,
                    agreement_id=agreement_id,
                    pdf_path=pdf_path,
                    signing_url=signing_url
                )
            except Exception as e:
                raise
            finally:
                # Clean up PDF file
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            
            return Agreement(
                id=agreement_id,
                title=title,
                content=content,
                recipient_email=recipient_email,
                created_at=datetime.fromtimestamp(current_time),
                face_embedding=None,
                status="pending"
            )
            
        except Exception as e:
            print(f"Error creating agreement: {str(e)}")
            raise
    
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
    
    def create_and_send_agreement(self, title: str, content: str, recipient_email: str, client_id: str) -> Agreement:
        """Create and send initial agreement (no face required)"""
        # Create agreement
        agreement = self.create_agreement(
            title=title,
            content=content,
            recipient_email=recipient_email,
            client_id=client_id
        )
        
        # Generate signing URL
        base_url = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")
        signing_url = f"{base_url}/sign/{agreement.id}"
        
        # Generate PDF
        pdf_path = self.pdf_generator.generate_agreement_pdf(
            agreement_id=agreement.id,
            title=title,
            content=content,
            recipient_email=recipient_email,
            signing_url=signing_url
        )
        
        # Send email
        try:
            self.email_sender.send_agreement_email(
                recipient_email=recipient_email,
                agreement_id=agreement.id,
                pdf_path=pdf_path,
                signing_url=signing_url
            )
            os.remove(pdf_path)
        except Exception as e:
            if os.path.exists(pdf_path):
                os.remove(pdf_path)
            raise
        
        return agreement

    def get_agreement_status(self, agreement_id: str) -> str:
        """Get the current status of an agreement"""
        # Get agreement from blockchain
        agreement_data = self.blockchain.get_agreement(agreement_id)
        
        if not agreement_data:
            return "not_found"
        
        # Check if agreement has been signed
        if agreement_data.get("signed_at"):
            return "signed"
        
        # Check if agreement has been created but not signed
        if agreement_data.get("created_at"):
            return "pending"
        
        return "unknown" 

    def process_signature(self, agreement_id: str, client_id: str, image_data: str, ip_address: str = None) -> Tuple[bool, str]:
        """Process signature with audit logging and IP tracking"""
        try:
            # Get agreement data first
            agreement_data = self.blockchain.get_agreement(agreement_id)
            if not agreement_data:
                self.db.log_audit_event(
                    agreement_id=agreement_id,
                    action_type='sign_attempt_failed',
                    actor_email=client_id,
                    metadata={'error': 'Agreement not found'},
                    ip_address=ip_address
                )
                return False, "Agreement not found"
            
            # Use recipient_email as client_id for consistency
            expected_client_id = agreement_data.get("recipient_email")
            
            # Verify client_id matches
            if client_id != expected_client_id:
                return False, f"Invalid client ID. Expected {expected_client_id}, got {client_id}"
            
            # Extract face and get embedding
            image_bytes = base64.b64decode(image_data.split(',')[1])
            face = self.face_extractor.extract_face_from_bytes(image_bytes)
            if face is None:
                return False, "No face detected in image"
            
            embedding = self.face_extractor.get_embedding(face)
            
            # Get the latest embedding for this client
            original_embedding, embedding_ref = self.vector_store.get_latest_client_embedding(client_id)
            
            if original_embedding is None:
                # Check if ID has been verified
                if not self.vector_store.has_verified_identity(client_id):
                    return False, "Please complete identity verification first"
                
                # First time signing
                # Add verification metadata for first-time signing
                self.db.log_audit_event(
                    agreement_id=agreement_id,
                    action_type='verification_attempt',
                    actor_email=client_id,
                    metadata={
                        'success': 'true',
                        'similarity_score': 1.0,
                        'first_time': True,
                        'timestamp': datetime.now().isoformat()
                    },
                    ip_address=ip_address
                )
                
                embedding_ref = self.vector_store.store_embedding(embedding, client_id, agreement_id)
                if not embedding_ref:
                    return False, "Failed to store face embedding"
                
                # Use consistent timestamp precision
                timestamp = round(time.time(), 6)  # Round to microseconds
                
                signature = self.generate_signature(
                    face_embedding=embedding,
                    agreement_id=agreement_id,
                    client_id=client_id,
                    timestamp=timestamp
                )
                
                # Store signature in blockchain with same timestamp
                self.blockchain.add_signature(
                    agreement_id=agreement_id,
                    signature_timestamp=timestamp,
                    embedding_reference=embedding_ref
                )
                
                # Mine block and update status with signature
                self.blockchain.mine_pending_transactions()
                self.db.update_agreement_status(agreement_id, "signed", signature)
                
                # Get agreement details and send PDF
                try:
                    self._send_signed_pdf(agreement_id, client_id, embedding, signature)
                except Exception as pdf_error:
                    print(f"Error generating/sending PDF: {str(pdf_error)}")
                    # Log error but continue with success response
                    self.db.log_audit_event(
                        agreement_id=agreement_id,
                        action_type='error',
                        actor_email=client_id,
                        metadata={
                            'error_type': 'pdf_generation',
                            'error_message': str(pdf_error)
                        },
                        ip_address=ip_address
                    )
                
                # Log successful first-time signature
                self.db.log_audit_event(
                    agreement_id=agreement_id,
                    action_type='signed',
                    actor_email=client_id,
                    metadata={
                        'signature_timestamp': datetime.now().isoformat(),
                        'verification_method': 'facial_biometrics',
                        'first_time_signing': True
                    },
                    ip_address=ip_address
                )
                
                return True, "Agreement signed successfully. A copy has been sent to your email."
                
            else:
                # Verify against existing embedding
                similarity_score, is_same_person = self.face_comparer.compare_face_embeddings(embedding, original_embedding)
                
                # Log verification attempt
                self.db.log_audit_event(
                    agreement_id=agreement_id,
                    action_type='verification_attempt',
                    actor_email=client_id,
                    metadata={
                        'success': str(similarity_score >= 0.85),
                        'similarity_score': float(similarity_score),
                        'timestamp': datetime.now().isoformat()
                    },
                    ip_address=ip_address
                )
                
                if similarity_score < 0.85:
                    return False, f"Face verification failed (similarity: {similarity_score:.2f})"
                
                # Store new embedding and add signature with normalized timestamp
                new_ref = self.vector_store.store_embedding(embedding, client_id, agreement_id)
                # Use consistent timestamp precision
                timestamp = round(time.time(), 6)  # Round to microseconds
                
                signature = self.generate_signature(
                    face_embedding=embedding,
                    agreement_id=agreement_id,
                    client_id=client_id,
                    timestamp=timestamp
                )
                
                self.blockchain.add_signature(
                    agreement_id=agreement_id,
                    signature_timestamp=timestamp,
                    embedding_reference=new_ref
                )
                
                # Mine block and update status
                self.blockchain.mine_pending_transactions()
                self.db.update_agreement_status(agreement_id, "signed", signature)
                
                # Send signed PDF
                try:
                    self._send_signed_pdf(agreement_id, client_id, embedding, signature)
                except Exception as pdf_error:
                    print(f"Error generating/sending PDF: {str(pdf_error)}")
                    self.db.log_audit_event(
                        agreement_id=agreement_id,
                        action_type='error',
                        actor_email=client_id,
                        metadata={
                            'error_type': 'pdf_generation',
                            'error_message': str(pdf_error)
                        },
                        ip_address=ip_address
                    )
                
                # Log successful signature
                self.db.log_audit_event(
                    agreement_id=agreement_id,
                    action_type='signed',
                    actor_email=client_id,
                    metadata={
                        'signature_timestamp': datetime.now().isoformat(),
                        'verification_method': 'facial_biometrics',
                        'similarity_score': float(similarity_score)
                    },
                    ip_address=ip_address
                )
                
                return True, f"Agreement signed successfully (similarity: {similarity_score:.2f})"
                
        except Exception as e:
            # Log error
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='error',
                actor_email=client_id,
                metadata={
                    'error_type': e.__class__.__name__,
                    'error_message': str(e)
                },
                ip_address=ip_address
            )
            raise

    def cancel_agreement(self, agreement_id: str, client_id: str, ip_address: str = None) -> Tuple[bool, str]:
        """Cancel agreement with audit logging"""
        try:
            # Get agreement data
            agreement_data = self.blockchain.get_agreement(agreement_id)
            if not agreement_data:
                return False, "Agreement not found"
            
            # Get agreement details for PDF cleanup
            details = self.db.get_agreement_details(agreement_id)
            
            # Verify client has permission to cancel
            if client_id != agreement_data.get("recipient_email"):
                return False, "Not authorized to cancel this agreement"
            
            # Add cancellation to blockchain
            self.blockchain.add_cancellation(agreement_id, client_id, round(time.time(), 6))
            self.blockchain.mine_pending_transactions()
            
            # Update status in database
            self.db.cancel_agreement(agreement_id)
            
            # Clean up PDF if it exists
            if details and details.get('pdf_path') and os.path.exists(details['pdf_path']):
                os.remove(details['pdf_path'])
            
            # Log cancellation with IP address
            self.db.log_audit_event(
                agreement_id=agreement_id,
                action_type='cancelled',
                actor_email=client_id,
                metadata={
                    'cancellation_timestamp': datetime.now().isoformat(),
                    'reason': 'user_requested'
                },
                ip_address=ip_address
            )
            
            return True, "Agreement cancelled successfully"
            
        except Exception as e:
            return False, f"Error cancelling agreement: {str(e)}"

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

    def _send_signed_pdf(self, agreement_id: str, client_id: str, embedding: np.ndarray, signature: str):
        """Generate and send signed PDF to the client"""
        signed_pdf_path = None
        try:
            # Get agreement details
            agreement_data = self.db.get_agreement_details(agreement_id)
            if not agreement_data:
                raise Exception("Agreement not found")
            
            # Check if this is an uploaded PDF
            if agreement_data.get('pdf_path'):
                original_pdf_path = agreement_data['pdf_path']
                if not os.path.exists(original_pdf_path):
                    raise Exception(f"Original PDF not found at: {original_pdf_path}")
                    
                # Append signature page to uploaded PDF
                signed_pdf_path = self.pdf_generator.append_signature_page(
                    original_pdf_path=original_pdf_path,
                    agreement_id=agreement_id,
                    signature=signature
                )
            else:
                # Generate new PDF for drafted agreement
                signed_pdf_path = self.pdf_generator.generate_signed_pdf(
                    agreement_id=agreement_id,
                    title=agreement_data['title'],
                    content=agreement_data['content'],
                    recipient_email=client_id,
                    signature=signature
                )
            
            # Send email with signed PDF
            try:
                self.email_sender.send_signed_agreement_email(
                    recipient_email=client_id,
                    agreement_id=agreement_id,
                    pdf_path=signed_pdf_path,
                    signature=signature
                )
                
                # Clean up original PDF after successful sending
                if agreement_data.get('pdf_path') and os.path.exists(agreement_data['pdf_path']):
                    os.remove(agreement_data['pdf_path'])
                    
            except Exception as e:
                print(f"Error sending signed agreement email: {str(e)}")
                raise
            
        except Exception as e:
            print(f"Error in _send_signed_pdf: {str(e)}")
            raise
        
        finally:
            # Clean up signed PDF
            if signed_pdf_path and os.path.exists(signed_pdf_path):
                os.remove(signed_pdf_path)

    def create_agreement_from_pdf(self, title: str, recipient_email: str, pdf_file, client_id: str, ip_address: str = None) -> Agreement:
        """Create a new agreement from an uploaded PDF file"""
        temp_pdf_path = None
        try:
            
            # Create unique ID for agreement
            agreement_data = f"{title}{recipient_email}{datetime.now().isoformat()}"
            agreement_id = hashlib.sha512(agreement_data.encode()).hexdigest()[:16]
            
            # Save PDF in persistent temp directory with unique name
            temp_pdf_path = os.path.join('temp_agreements', f"upload_{agreement_id}.pdf")
            os.makedirs('temp_agreements', exist_ok=True)
            pdf_file.save(temp_pdf_path)
            
            # Store reference in blockchain
            transaction_id = self.blockchain.add_agreement(
                agreement_id=agreement_id,
                recipient_email=recipient_email,
                embedding_reference=None,
                client_id=client_id,
                timestamp=round(time.time(), 6)
            )
            
            # Mine the block
            block = self.blockchain.mine_pending_transactions()
            if not block:
                raise Exception("Failed to mine block for agreement")
            
            # Store agreement details with empty string for content
            self.db.store_agreement_details({
                'agreement_id': agreement_id,
                'title': title,
                'content': '',  # Empty string for uploaded PDFs
                'recipient_email': recipient_email,
                'status': 'pending',
                'pdf_path': temp_pdf_path
            })
            
            # Generate signing URL
            base_url = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")
            signing_url = f"{base_url}/sign/{agreement_id}"
            
            # Send email with original PDF
            self.email_sender.send_agreement_email(
                recipient_email=recipient_email,
                agreement_id=agreement_id,
                pdf_path=temp_pdf_path,
                signing_url=signing_url
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
                content='',  # Changed from None to empty string
                recipient_email=recipient_email,
                created_at=datetime.now(),
                face_embedding=None,
                status="pending"
            )
            
        except Exception as e:
            # Only clean up PDF on error
            if temp_pdf_path and os.path.exists(temp_pdf_path):
                try:
                    os.remove(temp_pdf_path)
                except Exception as cleanup_error:
                    print(f"Error cleaning up PDF: {str(cleanup_error)}")
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