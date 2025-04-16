from typing import List, Optional, Tuple
import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.http import models
import os
from datetime import datetime
from dotenv import load_dotenv
import uuid
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from src.utils.timezone_utils import chicago_now

class VectorStore:
    def __init__(self):
        load_dotenv()
        
        # Initialize Qdrant client with credentials from .env
        self.client = QdrantClient(
            url=os.getenv("QDRANT_ENDPOINT"),
            api_key=os.getenv("QDRANT_API_KEY")
        )
        
        # Setup encryption
        encryption_key = os.getenv("AES_ENCRYPTION_KEY")
        if not encryption_key:
            raise ValueError("AES_ENCRYPTION_KEY must be set in .env")
            
        salt = b"fixed_salt"  # You might want to store this securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
        self.fernet = Fernet(key)
        
        self.collection_name = "face_embeddings"
        self._ensure_collection_exists()
        
    def _ensure_collection_exists(self):
        """Ensure the face embeddings collection exists with proper schema"""
        try:
            # Try to get existing collection
            collection_info = self.client.get_collection(self.collection_name)
            
            # Check if dimensions match
            if collection_info.config.params.vectors.size != 512:
                # Delete and recreate if dimensions don't match
                self.client.delete_collection(self.collection_name)
                raise ValueError("Collection exists with wrong dimensions")
            
        except:
            # Create new collection
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=models.VectorParams(
                    size=512,  # FaceNet embedding size is 512 for default model
                    distance=models.Distance.COSINE
                )
            )
            
    def _encrypt_vector(self, vector: np.ndarray) -> bytes:
        """Encrypt a vector using AES-256"""
        vector_bytes = vector.tobytes()
        return self.fernet.encrypt(vector_bytes)

    def _decrypt_vector(self, encrypted_data: bytes) -> np.ndarray:
        """Decrypt a vector using AES-256"""
        vector_bytes = self.fernet.decrypt(encrypted_data)
        return np.frombuffer(vector_bytes, dtype=np.float32)

    def get_latest_client_embedding(self, client_id: str) -> Tuple[Optional[np.ndarray], Optional[str]]:
        """Get the most recent embedding for a client"""
        try:
            search_result = self.client.scroll(
                collection_name=self.collection_name,
                scroll_filter=models.Filter(
                    must=[
                        models.FieldCondition(
                            key="client_id",
                            match=models.MatchValue(value=client_id)
                        )
                    ]
                ),
                with_payload=True,
                limit=1
            )
            
            if search_result and search_result[0]:
                point = search_result[0][0]
                encrypted_data = b64decode(point.payload["encrypted_embedding"])
                vector = self._decrypt_vector(encrypted_data)
                
                if vector.size != 512:
                    print(f"Warning: Retrieved vector has unexpected size: {vector.size}")
                    return None, None
                    
                return vector, str(point.id)
            
            return None, None
            
        except Exception as e:
            print(f"Error getting latest embedding: {str(e)}")
            return None, None
    
    def store_embedding(self, embedding: np.ndarray, client_id: str, contract_id: str, verified: bool = False) -> str:
        """Store embedding and return reference ID"""
        point_uuid = str(uuid.uuid4())
        
        # Ensure embedding is 1D array and encrypt it
        vector = np.asarray(embedding).reshape(-1)
        encrypted_vector = self._encrypt_vector(vector)
        
        # Store with encrypted embedding and plaintext metadata
        self.client.upsert(
            collection_name=self.collection_name,
            points=[
                models.PointStruct(
                    id=point_uuid,
                    vector=[0] * 512,  # Placeholder vector
                    payload={
                        "encrypted_embedding": b64encode(encrypted_vector).decode(),
                        "client_id": client_id,
                        "contract_id": contract_id,
                        "timestamp": chicago_now().isoformat(),
                        "verified_identity": verified
                    }
                )
            ]
        )
        
        return point_uuid
        
    def get_embedding(self, reference_id: str) -> Optional[np.ndarray]:
        """Retrieve embedding by reference ID"""
        try:
            points = self.client.retrieve(
                collection_name=self.collection_name,
                ids=[reference_id],
                with_vectors=True  # Make sure we get the vectors back
            )
            
            if not points:
                return None
            
            # Convert to numpy array and ensure correct shape
            vector = np.array(points[0].vector, dtype=np.float32)
            if vector.size != 512:
                print(f"Warning: Retrieved vector has unexpected size: {vector.size}")
                return None
            
            return vector
        
        except Exception as e:
            print(f"Error retrieving embedding: {str(e)}")
            return None
    
    def update_metadata(self, reference_id: str, client_id: str, contract_id: str):
        """Update metadata for a stored embedding"""
        self.client.set_payload(
            collection_name=self.collection_name,
            payload={
                "client_id": client_id,
                "contract_id": contract_id,
                "timestamp": chicago_now().isoformat()
            },
            points=[reference_id]
        )
    
    def has_verified_identity(self, client_id: str) -> bool:
        """Check if a client has completed identity verification"""
        try:
            # Search for points with matching client_id and verified status
            search_result = self.client.scroll(
                collection_name=self.collection_name,
                scroll_filter=models.Filter(
                    must=[
                        models.FieldCondition(
                            key="client_id",
                            match=models.MatchValue(value=client_id)
                        ),
                        models.FieldCondition(
                            key="verified_identity",
                            match=models.MatchValue(value=True)
                        )
                    ]
                ),
                limit=1
            )
            
            return bool(search_result and search_result[0])
        
        except Exception as e:
            print(f"Error checking identity verification: {str(e)}")
            return False

    def find_similar_faces(self, query_embedding: np.ndarray, client_id: str, threshold: float = 0.6) -> Optional[dict]:
        """Compare query embedding with client's latest face embedding"""
        try:
            # Get only the latest embedding for the client
            latest_vector, point_id = self.get_latest_client_embedding(client_id)
            
            if latest_vector is None or point_id is None:
                return None
            
            query_embedding = np.asarray(query_embedding).reshape(-1)
            
            # Calculate cosine similarity
            similarity = np.dot(query_embedding, latest_vector) / (np.linalg.norm(query_embedding) * np.linalg.norm(latest_vector))
            
            if similarity >= threshold:
                # Get the point metadata
                point = self.client.retrieve(
                    collection_name=self.collection_name,
                    ids=[point_id],
                    with_payload=True
                )[0]
                
                # Create a clean payload without the encrypted embedding
                clean_payload = {
                    k: v for k, v in point.payload.items() 
                    if k != "encrypted_embedding"
                }
                
                return {
                    'id': point_id,
                    'similarity': float(similarity),
                    'payload': clean_payload
                }
            
            return None
            
        except Exception as e:
            print(f"Error finding similar faces: {str(e)}")
            return None 