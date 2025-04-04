import numpy as np
from scipy.spatial.distance import cosine
from typing import Tuple

class FaceComparer:
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        
    def calculate_similarity(self, embedding1, embedding2):
        """Calculate cosine similarity between two embeddings"""
        # Ensure both embeddings are 1D arrays of the same shape
        embedding1 = np.asarray(embedding1).reshape(-1)
        embedding2 = np.asarray(embedding2).reshape(-1)
        
        # Verify shapes match
        if embedding1.shape != embedding2.shape:
            raise ValueError(f"Embedding shapes do not match: {embedding1.shape} vs {embedding2.shape}")
        
        # Calculate cosine similarity
        similarity_score = 1 - cosine(embedding1, embedding2)
        return similarity_score
        
    def compare_face_embeddings(self, embedding1, embedding2) -> Tuple[float, bool]:
        """Compare two face embeddings and return similarity score and match status"""
        similarity_score = self.calculate_similarity(embedding1, embedding2)
        print(f"Similarity score: {similarity_score}")
        is_same_person = similarity_score >= self.similarity_threshold
        return similarity_score, is_same_person