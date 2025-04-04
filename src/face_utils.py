from PIL import Image
from numpy import asarray
from keras_facenet import FaceNet
import cv2
import numpy as np
from typing import Tuple, List
import time

class FaceExtractor:
    def __init__(self):
        self.embedder = FaceNet()
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        self.eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
        self.smile_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_smile.xml')
        
        # Liveness detection state
        self.last_face_position = None
        self.blink_counter = 0
        self.smile_detected = False
        self.head_positions = []
        self.last_check_time = time.time()
        self.challenge_sequence = []
        self.current_challenge = None
        
        # Additional liveness detection parameters
        self.frame_history = []
        self.max_frame_history = 30
        self.brightness_history = []
        self.last_frame_time = time.time()
        
        # Anti-spoofing parameters - adjusted for better balance
        self.min_face_size = (130, 130)  # Reduced minimum size requirement
        self.texture_threshold = 12.0     # Slightly reduced texture threshold
        self.edge_density_threshold = 15.0 # Increased edge threshold
        self.brightness_std_threshold = 1.5 # Increased brightness variation threshold
        
        # Face position parameters calibrated for better usability
        self.face_position_params = {
            'center_tolerance': 45,      # Increased tolerance (~15% of guide width)
            'size_min_ratio': 0.50,     # Face must take up at least 45% of video width
            'size_max_ratio': 0.85,     # Face can take up to 85% of video width
            'stable_frames_required': 2, # Reduced stability requirement
            'aspect_ratio_tolerance': 0.2, # Increased aspect ratio tolerance to 20%
            'guide_width_px': 220,      # Keep guide dimensions
            'guide_height_px': 280,
            'video_width': 640,         # Keep video dimensions
            'video_height': 480,
            'auto_capture_threshold': 3  # Reduced frames needed for auto-capture
        }
        self.stable_position_frames = 0
        
    def extract_face(self, filename, required_size=(160, 160)):
        """
        Extracts a face from an image file, crops it to a square,
        and resizes it to the required size using bicubic interpolation.

        Args:
            filename (str): Path to the image file.
            required_size (tuple): Desired size for the extracted face (default is (160, 160)).

        Returns:
            numpy.ndarray: Array representing the extracted and resized face.
        """
        image = Image.open(filename)
        image = image.convert('RGB')

        # Crop to square
        width, height = image.size
        size = min(width, height)
        left = (width - size) // 2
        top = (height - size) // 2
        right = (width + size) // 2
        bottom = (height + size) // 2
        image = image.crop((left, top, right, bottom))

        # Resize using bicubic interpolation
        image = image.resize(required_size, resample=Image.BICUBIC)

        face_array = asarray(image)
        return face_array

    def get_embedding(self, face):
        """Generates embeddings from the extracted face"""
        # Ensure face is in correct format for FaceNet
        face_pixels = face.astype('float32')
        
        # Get embedding using FaceNet
        samples = np.expand_dims(face_pixels, axis=0)  # Add batch dimension
        embedding = self.embedder.embeddings(samples)
        
        # Ensure we return a 512-dimensional 1D array
        embedding_1d = embedding.reshape(-1)
        
        # Verify the shape is correct (512 dimensions)
        if embedding_1d.shape != (512,):
            raise ValueError(f"Unexpected embedding shape: {embedding_1d.shape}, expected (512,)")
        
        return embedding_1d

    def detect_liveness(self, frame) -> Tuple[bool, str]:
        """Enhanced liveness detection with stricter anti-spoofing"""
        # 1. Check frame timing
        current_time = time.time()
        frame_delta = current_time - self.last_frame_time
        if frame_delta < 0.01 or frame_delta > 0.1:
            return False, "Invalid frame timing"
        self.last_frame_time = current_time
        
        # 2. Early screen artifact check
        if self._detect_screen_artifacts(frame):
            return False, "Spoof attempt detected - please use live camera"
            
        # 3. Check frame quality
        if frame.shape[0] < self.min_face_size[0] or frame.shape[1] < self.min_face_size[1]:
            return False, "Image resolution too low"
            
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
        
        if len(faces) != 1:
            return False, "Please ensure exactly one face is visible"
            
        for (x,y,w,h) in faces:
            # Size check
            if w < self.min_face_size[0] or h < self.min_face_size[1]:
                return False, "Please move closer to the camera"
                
            roi_gray = gray[y:y+h, x:x+w]
            roi_color = frame[y:y+h, x:x+w]
            
            # Additional texture analysis for the face region
            if self._detect_screen_or_print(roi_gray):
                return False, "Please use a real face, not a photo"
                
            # 4. Motion Analysis
            current_position = (x + w//2, y + h//2)
            if not self._check_natural_movement(current_position):
                return False, "Please move your head naturally"
            
            # 5. Challenge-Response Tests
            if not self.current_challenge:
                self.current_challenge = self._get_next_challenge()
            
            challenge_complete, message = self._process_challenge(roi_gray, roi_color)
            if challenge_complete:
                self.current_challenge = None
                if len(self.challenge_sequence) == 0:  # All challenges completed
                    return True, "Identity verified! You may proceed."
            
            # Draw facial landmarks and status
            self._draw_debug_info(frame, (x,y,w,h), roi_color)
            
            return False, f"Please {message}"
            
        return False, "Face not detected"
    
    def _detect_screen_or_print(self, roi_gray) -> bool:
        """Detect if image is from a screen or printed photo"""
        # Texture analysis using FFT
        f = np.fft.fft2(roi_gray)
        fshift = np.fft.fftshift(f)
        magnitude_spectrum = 20*np.log(np.abs(fshift))
        
        # Check for regular patterns (screens typically have them)
        if np.max(magnitude_spectrum) > 90:  # Threshold for screen detection
            return True
            
        # Check for moire patterns
        if np.std(magnitude_spectrum) < 10:  # Threshold for print detection
            return True
            
        return False
    
    def _check_natural_movement(self, current_pos) -> bool:
        """Verify natural head movement patterns"""
        if self.last_face_position:
            movement = self._calculate_movement(self.last_face_position, current_pos)
            
            # Too still or too jerky movement detection
            if movement < 0.1:  # Too still (might be a photo)
                return False
            if movement > 50:  # Too jerky (unnatural movement)
                return False
                
            # Store movement history
            self.head_positions.append(current_pos)
            if len(self.head_positions) > 30:  # Keep last 30 frames
                self.head_positions.pop(0)
                
            # Check for natural movement patterns
            if len(self.head_positions) > 10:
                if self._is_movement_too_regular():
                    return False
                    
        self.last_face_position = current_pos
        return True
    
    def _is_movement_too_regular(self) -> bool:
        """Check if movement pattern is too regular (might be a video loop)"""
        movements = [self._calculate_movement(self.head_positions[i], self.head_positions[i+1]) 
                    for i in range(len(self.head_positions)-1)]
        return np.std(movements) < 0.1  # Too regular movement
    
    def _get_next_challenge(self) -> str:
        """Get next liveness challenge"""
        if not self.challenge_sequence:
            self.challenge_sequence = [
                'blink',
                'smile',
                'look_left',
                'look_right'
            ]
            np.random.shuffle(self.challenge_sequence)
        return self.challenge_sequence.pop(0)
    
    def _process_challenge(self, roi_gray, roi_color) -> Tuple[bool, str]:
        """Process current liveness challenge"""
        if self.current_challenge == 'blink':
            eyes = self.eye_cascade.detectMultiScale(roi_gray)
            if len(eyes) < 2:
                self.blink_counter += 1
                if self.blink_counter > 3:  # Confirmed blink
                    self.blink_counter = 0
                    return True, "blink detected"
            return False, "blink your eyes"
            
        elif self.current_challenge == 'smile':
            smiles = self.smile_cascade.detectMultiScale(roi_gray, 1.7, 20)
            if len(smiles) > 0:
                return True, "smile detected"
            return False, "smile"
            
        elif self.current_challenge == 'look_left':
            # Use eye position relative to face to detect looking left
            eyes = self.eye_cascade.detectMultiScale(roi_gray)
            if len(eyes) == 2 and self._is_looking_left(eyes):
                return True, "left turn detected"
            return False, "look left"
            
        elif self.current_challenge == 'look_right':
            eyes = self.eye_cascade.detectMultiScale(roi_gray)
            if len(eyes) == 2 and self._is_looking_right(eyes):
                return True, "right turn detected"
            return False, "look right"
            
        return False, "follow instructions"
    
    def _is_looking_left(self, eyes) -> bool:
        """Detect if person is looking left"""
        left_eye, right_eye = sorted(eyes, key=lambda x: x[0])[:2]
        return abs(left_eye[0] - right_eye[0]) > 20
    
    def _is_looking_right(self, eyes) -> bool:
        """Detect if person is looking right"""
        left_eye, right_eye = sorted(eyes, key=lambda x: x[0])[:2]
        return abs(left_eye[0] - right_eye[0]) > 20
    
    def _draw_debug_info(self, frame, face_rect, roi_color):
        """Draw debug information on frame"""
        x,y,w,h = face_rect
        cv2.rectangle(frame, (x,y), (x+w,y+h), (255,0,0), 2)
        
        # Draw challenge status
        if self.current_challenge:
            cv2.putText(frame, f"Challenge: {self.current_challenge}", 
                       (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,0), 2)
        
        # Draw remaining challenges
        remaining = len(self.challenge_sequence)
        cv2.putText(frame, f"Remaining: {remaining}", 
                   (10, 90), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,0), 2)
    
    def _calculate_movement(self, prev_pos: Tuple[int, int], curr_pos: Tuple[int, int]) -> float:
        """Calculate movement distance between two positions"""
        return np.sqrt((prev_pos[0] - curr_pos[0])**2 + (prev_pos[1] - curr_pos[1])**2)

    def extract_face_from_bytes(self, image_bytes: bytes, required_size=(160, 160), min_face_size=None) -> np.ndarray:
        try:
            # Convert bytes to numpy array
            nparr = np.frombuffer(image_bytes, np.uint8)
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if image is None:
                print("Failed to decode image")
                return None
            
            # Convert to grayscale for face detection
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
            
            if len(faces) == 0:
                print("No faces detected")
                return None
            
            # Find the largest face by area
            largest_face = None
            largest_area = 0
            
            for (x, y, w, h) in faces:
                area = w * h
                if area > largest_area:
                    largest_area = area
                    largest_face = (x, y, w, h)
                    
            if largest_face is None:
                print("No valid faces found")
                return None
            
            # Extract the largest face
            x, y, w, h = largest_face
            
            # Modify padding (reduce from 40% to 20% of face dimensions)
            padding_x = int(w * 0.25)  # Reduced from 0.40
            padding_y = int(h * 0.25)  # Reduced from 0.40
            
            # Calculate coordinates with padding
            x1 = max(0, x - padding_x)
            y1 = max(0, y - padding_y)
            x2 = min(image.shape[1], x + w + padding_x)
            y2 = min(image.shape[0], y + h + padding_y)
            
            # Extract face with padding
            face_with_padding = image[y1:y2, x1:x2]
            
            # Check minimum face size if specified
            if min_face_size and (face_with_padding.shape[0] < min_face_size[1] or face_with_padding.shape[1] < min_face_size[0]):
                print(f"Largest face too small: {face_with_padding.shape[:2]} < {min_face_size}")
                return None
                
            # Resize maintaining aspect ratio
            aspect_ratio = face_with_padding.shape[1] / face_with_padding.shape[0]
            if aspect_ratio > 1:
                new_width = required_size[0]
                new_height = int(new_width / aspect_ratio)
            else:
                new_height = required_size[1]
                new_width = int(new_height * aspect_ratio)
                
            face = cv2.resize(face_with_padding, (new_width, new_height), interpolation=cv2.INTER_LANCZOS4)
                
            # Create a white canvas of the required size
            final_image = np.ones((required_size[1], required_size[0], 3), dtype=np.uint8) * 255
                
            # Calculate position to paste the resized face
            y_offset = (required_size[1] - face.shape[0]) // 2
            x_offset = (required_size[0] - face.shape[1]) // 2
                
            # Paste the face onto the white canvas
            final_image[y_offset:y_offset+face.shape[0], x_offset:x_offset+face.shape[1]] = face
                
            return final_image
            
        except Exception as e:
            print(f"Error extracting face from bytes: {str(e)}")
            print(f"Image bytes length: {len(image_bytes)}")  # Debug log
            return None

    def _detect_screen_artifacts(self, frame) -> bool:
        """Enhanced screen artifact detection"""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        # 1. Enhanced Moiré pattern detection
        blur = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Laplacian(blur, cv2.CV_64F)
        edge_density = np.mean(np.abs(edges))
        
        # 2. Improved brightness analysis
        brightness = np.mean(gray)
        self.brightness_history.append(brightness)
        if len(self.brightness_history) > 10:
            self.brightness_history.pop(0)
            
        # 3. Texture analysis using Local Binary Patterns (LBP)
        texture_score = self._calculate_texture_score(gray)
        
        # 4. Check reflection patterns
        reflection_detected = self._detect_reflections(gray)
        
        # Fail if any of these conditions are met
        if (edge_density > self.edge_density_threshold or  # Screen edges
            texture_score < self.texture_threshold or      # Artificial texture
            reflection_detected or                         # Screen reflections
            (len(self.brightness_history) > 5 and         # Unnatural brightness
             np.std(self.brightness_history) < self.brightness_std_threshold)):
            return True
            
        return False
        
    def _calculate_texture_score(self, gray_img) -> float:
        """Calculate texture naturalness score"""
        # Simple gradient-based texture analysis
        gradient_x = cv2.Sobel(gray_img, cv2.CV_64F, 1, 0, ksize=3)
        gradient_y = cv2.Sobel(gray_img, cv2.CV_64F, 0, 1, ksize=3)
        gradient_magnitude = np.sqrt(gradient_x**2 + gradient_y**2)
        return np.std(gradient_magnitude)
        
    def _detect_reflections(self, gray_img) -> bool:
        """Detect unnatural reflection patterns"""
        # Apply threshold to find bright spots
        _, binary = cv2.threshold(gray_img, 200, 255, cv2.THRESH_BINARY)
        
        # Find contours of bright regions
        contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        # Check for regular-shaped reflections
        for contour in contours:
            if len(contour) > 4:  # Skip tiny contours
                # Check if the contour is too regular (screen reflection)
                perimeter = cv2.arcLength(contour, True)
                area = cv2.contourArea(contour)
                if area > 0:  # Avoid division by zero
                    circularity = 4 * np.pi * area / (perimeter * perimeter)
                    if circularity > 0.8:  # Too circular = likely screen reflection
                        return True
        return False

    def validate_face_position(self, image_bytes) -> Tuple[bool, str, bool]:
        """Validate face position within the guide and handle countdown"""
        try:
            # Convert bytes to numpy array
            nparr = np.frombuffer(image_bytes, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            # Convert to grayscale for face detection
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
            
            if len(faces) == 0:
                self.stable_position_frames = 0
                return False, "No face detected", False
            if len(faces) > 1:
                self.stable_position_frames = 0
                return False, "Multiple faces detected", False
            
            # Get face dimensions and position
            x, y, w, h = faces[0]
            
            # Calculate frame center and face center
            frame_center_x = frame.shape[1] // 2
            frame_center_y = frame.shape[0] // 2
            face_center_x = x + w // 2
            face_center_y = y + h // 2
            
            # Get parameters
            params = self.face_position_params
            
            # Check face position
            if abs(face_center_x - frame_center_x) > params['center_tolerance']:
                self.stable_position_frames = 0
                return False, "Center your face horizontally", False
            if abs(face_center_y - frame_center_y) > params['center_tolerance']:
                self.stable_position_frames = 0
                return False, "Center your face vertically", False
            
            # Check face size
            face_ratio = max(w / frame.shape[1], h / frame.shape[0])
            if face_ratio < params['size_min_ratio']:
                self.stable_position_frames = 0
                return False, "Move closer to the camera", False
            if face_ratio > params['size_max_ratio']:
                self.stable_position_frames = 0
                return False, "Move further from the camera", False
            
            # If we got here, position is good - increment stable counter
            self.stable_position_frames += 1
            
            # Check if position has been stable for enough frames
            if self.stable_position_frames < params['stable_frames_required']:
                return False, "Hold still...", False
            
            # Start countdown once position is stable
            countdown = 3 - (self.stable_position_frames - params['stable_frames_required'])
            if countdown > 0:
                return False, f"Capturing in {countdown}...", False
            
            # Trigger capture on countdown complete
            if self.stable_position_frames == params['stable_frames_required'] + 3:
                return True, "Face captured!", True
            
            return False, "Hold still...", False
            
        except Exception as e:
            self.stable_position_frames = 0
            return False, f"Error validating face position: {str(e)}", False