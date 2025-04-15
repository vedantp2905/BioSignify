from flask import Flask, render_template, request, jsonify, session, g
from src.agreement_manager import AgreementManager
import os
from dotenv import load_dotenv
import base64
from datetime import datetime, timedelta
from src.utils.session_manager import SessionManager
from flask_wtf.csrf import CSRFProtect
from flask import redirect, url_for
from functools import wraps
from src.face_utils import FaceExtractor
import secrets
from flask import Response
import cv2
import json
from flask_swagger_ui import get_swaggerui_blueprint
from flask import send_from_directory
import werkzeug
import hashlib
from io import BytesIO

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
    static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
)
load_dotenv()

SIGNING_BASE_URL = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")

print("Initializing agreement manager...")
agreement_manager = AgreementManager()
face_extractor = FaceExtractor()

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

csrf = CSRFProtect(app)

# Set secret key for CSRF
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Add secret key for sessions
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key')  # Change in production

# Add session and rate limiting middleware
@app.before_request
def before_request():

    if not hasattr(app, 'session_manager'):
        app.session_manager = SessionManager()
    
    # List of endpoints that don't require authentication
    public_endpoints = ['login', 'static', 'health_check']
    
    
    # Skip authentication for public endpoints
    if request.endpoint in public_endpoints:
        return
        
    # Validate session for protected routes
    token = session.get('session_token')
    if not token:
        return redirect(url_for('login'))
    
    user_data = app.session_manager.validate_session(token)
    if not user_data:
        session.clear()
        return redirect(url_for('login'))
    
    g.user = user_data

@app.route('/health')
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Service is running',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/sign/<agreement_id>', methods=['GET'])
def sign_page(agreement_id):
    try:
        print(f"DEBUG - Sign page requested for agreement: {agreement_id}")
        agreement_manager = AgreementManager()
        agreement_data = agreement_manager.db.get_agreement_details(agreement_id)
        
        if not agreement_data:
            print(f"ERROR - No agreement found with ID: {agreement_id}")
            return render_template('error.html', 
                                 message=f"Agreement not found. Please check the link and try again.")
        
        # Check if agreement is already signed
        status = agreement_manager.get_agreement_status(agreement_id)
        if status == "signed":
            return render_template('already_signed.html')
        
        client_id = agreement_data['recipient_email']
        
        # Check if user needs ID verification
        needs_verification = not agreement_manager.vector_store.has_verified_identity(client_id)
        
        if needs_verification:
            return render_template('id_verification.html',
                agreement_id=agreement_id,
                client_id=client_id
            )
        
        return render_template('sign_page.html', 
            agreement_id=agreement_id,
            client_id=client_id
        )
    except Exception as e:
        print(f"ERROR - Error in sign_page: {str(e)}")
        import traceback
        traceback.print_exc()
        return render_template('error.html', 
                             message="An error occurred loading the agreement. Please try again later.")

def get_client_ip():
    """Get client IP from request, handling proxy forwarding"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

@app.route('/api/sign', methods=['POST'])
def sign_agreement():
    try:
        client_ip = get_client_ip()
        
        if not g.user:
            return jsonify({
                'success': False,
                'message': 'Invalid session'
            }), 401
        
        # Get agreement data from request
        data = request.get_json() if request.is_json else request.form
        agreement_id = data.get('agreement_id')
        client_id = data.get('client_id')
        
        if not agreement_id or not client_id:
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
            
        # Check agreement status
        agreement = agreement_manager.db.get_agreement_details(agreement_id)
        if not agreement:
            return jsonify({
                'success': False,
                'message': 'Agreement not found'
            }), 404
            
        if agreement.get('status') != 'pending':
            return jsonify({
                'success': False,
                'message': f'Agreement cannot be signed (status: {agreement.get("status")})'
            }), 400
            
        # Process signature
        success, transaction_id = agreement_manager.process_signature(
            agreement_id=agreement_id,
            client_id=client_id,
            ip_address=client_ip
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Agreement signed successfully. Signed copies have been sent to all parties.',
                'agreement_id': agreement_id,
                'transaction_id': transaction_id
            })
            
        return jsonify({
            'success': False,
            'message': 'Failed to sign agreement'
        })
        
    except Exception as e:
        print(f"Error processing signature: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error processing signature: {str(e)}'
        }), 500

@app.route('/')
def home():
    """Home page with 4 cards"""
    return render_template('home.html')

@app.route('/pending-agreements')
def pending_agreements():
    """Pending agreements page"""
    return render_template('pending_agreements.html')

@app.route('/api/pending-agreements')
def get_pending_agreements():
    """API endpoint to get pending agreements"""
    try:
        # Get all agreements with pending status directly from agreement_details table
        response = agreement_manager.db.supabase.table('agreement_details') \
            .select('*') \
            .eq('status', 'pending') \
            .execute()
            
        agreements = []
        for agreement in response.data:
            agreements.append({
                'id': agreement['agreement_id'],
                'recipient_email': agreement['recipient_email'],
                'created_at': agreement['created_at'],
                'title': agreement['title']
            })
        
        return jsonify({'agreements': agreements})
    except Exception as e:
        print(f"Error getting pending agreements: {str(e)}")
        return jsonify({'error': 'Failed to fetch pending agreements'}), 500

@app.route('/agreement/<agreement_id>')
def view_agreement(agreement_id):
    """View agreement details page"""
    agreement = agreement_manager.db.get_agreement_details(agreement_id)
    if not agreement:
        return "Agreement not found", 404
    
    try:
        # Parse the timestamp string to datetime object
        if agreement.get('created_at'):
            # Remove timezone info if present
            created_at = agreement['created_at'].replace('T', ' ')
            if '+' in created_at:
                created_at = created_at.split('+')[0]
            agreement['created_at'] = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
        print(f"Error parsing date: {e}")
        # Provide a fallback datetime if parsing fails
        agreement['created_at'] = datetime.now()
        
    return render_template('agreement_details.html', agreement=agreement)

@app.route('/create-contract', methods=['GET', 'POST'])
def create_contract():
    if request.method == 'GET':
        return render_template('create_contract.html')
        
    try:
        data = request.get_json()
        client_ip = get_client_ip()
        
        if not g.user:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        print(f"DEBUG - Creating agreement with title: {data.get('title', 'Untitled Agreement')}")
        print(f"DEBUG - Content length: {len(data.get('content', ''))}")
        print(f"DEBUG - Recipient email: {data.get('recipient_email')}")
        
        # Create and send agreement (does everything in one call)
        agreement = agreement_manager.create_and_send_agreement(
            title=data.get('title', 'Untitled Agreement'),
            content=data.get('content', ''),
            recipient_email=data.get('recipient_email'),
            client_id=g.user['email']
        )
        
        print(f"DEBUG - Agreement created successfully: {agreement.id}")
        return jsonify({
            'success': True,
            'agreement_id': agreement.id,
            'message': 'Agreement created and sent successfully'
        })
        
    except Exception as e:
        print(f"DEBUG - Error creating contract: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/create-contract')
def create_contract_page():
    """Create contract page"""
    return render_template('create_contract.html')

@app.route('/api/cancel-agreement/<agreement_id>', methods=['POST'])
def cancel_agreement(agreement_id):
    try:
        if not g.user:
            return jsonify({'error': 'User not authenticated'}), 401
            
        client_ip = get_client_ip()
            
        success, message = agreement_manager.cancel_agreement(
            agreement_id=agreement_id, 
            client_id=g.user['email'],
            ip_address=client_ip
        )
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/signed-agreements')
def signed_agreements_page():
    """Signed agreements page"""
    return render_template('signed_agreements.html')

@app.route('/cancelled-agreements')
def cancelled_agreements_page():
    """Cancelled agreements page"""
    return render_template('cancelled_agreements.html')

@app.route('/api/signed-agreements')
def get_signed_agreements():
    """API endpoint to get signed agreements"""
    try:
        response = agreement_manager.db.supabase.table('agreement_details') \
            .select('*') \
            .eq('status', 'signed') \
            .execute()
            
        agreements = []
        for agreement in response.data:
            agreements.append({
                'id': agreement['agreement_id'],
                'recipient_email': agreement['recipient_email'],
                'created_at': agreement['created_at'],
                'title': agreement['title']
            })
        
        return jsonify({'agreements': agreements})
    except Exception as e:
        print(f"Error getting signed agreements: {str(e)}")
        return jsonify({'error': 'Failed to fetch signed agreements'}), 500

@app.route('/api/cancelled-agreements')
def get_cancelled_agreements():
    """API endpoint to get cancelled agreements"""
    try:
        response = agreement_manager.db.supabase.table('agreement_details') \
            .select('*') \
            .eq('status', 'cancelled') \
            .execute()
            
        agreements = []
        for agreement in response.data:
            agreements.append({
                'id': agreement['agreement_id'],
                'recipient_email': agreement['recipient_email'],
                'created_at': agreement['created_at'],
                'title': agreement['title']
            })
        
        return jsonify({'agreements': agreements})
    except Exception as e:
        print(f"Error getting cancelled agreements: {str(e)}")
        return jsonify({'error': 'Failed to fetch cancelled agreements'}), 500 

@app.route('/api/validate-face-position', methods=['POST'])
@csrf.exempt
def validate_face_position():
    try:
        client_ip = get_client_ip()
        
        # Get image data from request
        data = request.get_json()
        if not data or 'image' not in data:
            print(f"No image data received from IP: {client_ip}")
            return jsonify({
                'valid': False,
                'message': f'No image data received (IP: {client_ip})',
                'capture': False
            }), 400

        image_data = data['image']
        
        # Validate image data format
        if not isinstance(image_data, str):
            print(f"Invalid image data type from IP: {client_ip}")
            return jsonify({
                'valid': False,
                'message': f'Invalid image data type (IP: {client_ip})',
                'capture': False
            }), 400
            
        if not image_data.startswith('data:image'):
            print(f"Invalid image format from IP: {client_ip}")
            return jsonify({
                'valid': False,
                'message': f'Invalid image format (IP: {client_ip})',
                'capture': False
            }), 400

        try:
            # Extract base64 data
            image_base64 = image_data.split(',')[1]
            image_bytes = base64.b64decode(image_base64)
            
            # Call face validation logic
            success, message, should_capture = face_extractor.validate_face_position(image_bytes)
                        
            return jsonify({
                'valid': success,
                'message': f'{message} (IP: {client_ip})',
                'capture': should_capture
            })

        except Exception as e:
            print(f"Image processing error from IP {client_ip}: {str(e)}")
            return jsonify({
                'valid': False,
                'message': f'Image processing error: {str(e)} (IP: {client_ip})',
                'capture': False
            }), 400

    except Exception as e:
        print(f"Validation error from IP {get_client_ip()}: {str(e)}")
        return jsonify({
            'valid': False,
            'message': f'Validation error: {str(e)} (IP: {get_client_ip()})',
            'capture': False
        }), 500

@app.route('/api/agreements/<agreement_id>/audit-logs', methods=['GET'])
def get_agreement_audit_logs(agreement_id):
    try:
        print(f"DEBUG - API request for audit logs of agreement: {agreement_id}")
        
        # Get raw audit logs
        audit_logs = agreement_manager.db.get_agreement_audit_trail(agreement_id)
        print(f"DEBUG - Retrieved {len(audit_logs)} audit log entries")
        
        if not audit_logs:
            print(f"DEBUG - No audit logs found for agreement: {agreement_id}")
            # Check if the agreement exists
            agreement = agreement_manager.db.get_agreement_details(agreement_id)
            if not agreement:
                print(f"DEBUG - Agreement {agreement_id} not found")
                return jsonify([]), 404
                
            print(f"DEBUG - Agreement exists but no audit logs found")
            
        # Process logs to enhance them with more information
        enhanced_logs = []
        for log in audit_logs:
            try:
                print(f"DEBUG - Processing log: {log.get('action_type')} with ID: {log.get('transaction_id', 'N/A')}")
                
                enhanced_log = {
                    'action_type': log.get('action_type', 'unknown'),
                    'actor_email': log.get('actor_email', 'unknown'),
                    'timestamp': log.get('timestamp', ''),
                    'ip_address': log.get('ip_address', 'N/A'),
                    'transaction_id': log.get('transaction_id', 'N/A')
                }
                
                # Add metadata based on action type
                metadata = log.get('metadata', {})
                if isinstance(metadata, str):
                    try:
                        metadata = json.loads(metadata)
                    except:
                        metadata = {"data": metadata}
                
                # For 'created' events
                if log.get('action_type') == 'created':
                    enhanced_log['embedding_reference'] = metadata.get('embedding_reference', 'null')
                    enhanced_log['transaction_id'] = metadata.get('transaction_id', log.get('transaction_id', 'N/A'))
                    enhanced_log['recipient_email'] = metadata.get('recipient_email', 'N/A')
                    enhanced_log['type'] = metadata.get('type', 'agreement_creation')
                
                # For 'signed' events
                elif log.get('action_type') == 'signed':
                    enhanced_log['signature'] = metadata.get('signature', 'N/A')[:20] + '...' if metadata.get('signature') else 'N/A'
                    enhanced_log['embedding_reference'] = metadata.get('embedding_reference', 'N/A')
                    enhanced_log['verification_status'] = '[VERIFIED]' if metadata.get('embedding_reference') else 'N/A'
                    enhanced_log['transaction_id'] = metadata.get('transaction_id', log.get('transaction_id', 'N/A'))
                    
                # For verification attempts
                elif log.get('action_type') in ['verification_attempt', 'id_verification_attempt']:
                    enhanced_log['success'] = metadata.get('success', 'N/A')
                    enhanced_log['similarity_score'] = metadata.get('similarity_score', 'N/A')
                    enhanced_log['transaction_id'] = metadata.get('transaction_id', log.get('transaction_id', 'N/A'))
                
                # For record events
                elif log.get('action_type') == 'record':
                    enhanced_log['message'] = metadata.get('message', 'Historical record')
                    enhanced_log['status'] = metadata.get('status', 'unknown')
                    enhanced_log['recipient_email'] = metadata.get('recipient_email', 'N/A')
                
                enhanced_logs.append(enhanced_log)
                
            except Exception as e:
                print(f"ERROR - Failed to process audit log entry: {str(e)}")
                # Add raw log as fallback
                enhanced_logs.append({
                    'action_type': 'error_processing',
                    'actor_email': 'system',
                    'timestamp': datetime.utcnow().isoformat(),
                    'error': str(e),
                    'raw_log': str(log)
                })
        
        print(f"DEBUG - Returning {len(enhanced_logs)} processed audit logs")
        return jsonify(enhanced_logs)
        
    except Exception as e:
        print(f"ERROR - Failed to fetch audit logs: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Failed to fetch audit logs',
            'message': str(e)
        }), 500

@app.after_request
def add_security_headers(response):
    """Add security headers to every response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('session_token')
        if not token:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Please log in to access this resource'
            }), 401
        
        user_data = app.session_manager.validate_session(token)
        if not user_data:
            session.clear()
            return jsonify({
                'error': 'Session expired',
                'message': 'Please log in again'
            }), 401
            
        g.user = user_data
        return f(*args, **kwargs)
    return decorated_function

# Then define your routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
        
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            return jsonify({
                'error': 'Bad request',
                'message': 'Email is required'
            }), 400
        
        token = app.session_manager.create_session(
            user_id=email,
            email=email
        )
        session['session_token'] = token
        
        return jsonify({
            'success': True,
            'message': 'Logged in successfully'
        })
    
    return render_template('login.html')

@app.errorhandler(Exception)
def handle_error(error):
    # Handle 404 errors gracefully
    if isinstance(error, werkzeug.exceptions.NotFound):
        if request.path.endswith('favicon.ico'):
            return '', 404  # Return empty response for favicon
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'message': 'Resource not found'
            }), 404
        return render_template('404.html'), 404
        
    print(f"Unhandled error: {str(error)}") # Debug log
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500
    raise error

# Modify the run statement at the bottom of the file
if __name__ == '__main__':
    app.run( host='0.0.0.0', port=5000) 


@app.route('/api/verify/agreement/<agreement_id>')
def verify_agreement(agreement_id):
    try:
        # Get agreement details first
        agreement = agreement_manager.db.get_agreement_details(agreement_id)
        if not agreement:
            return jsonify({
                'success': False,
                'message': 'Agreement not found'
            }), 404

        # Get audit logs
        audit_logs = agreement_manager.db.get_agreement_audit_trail(agreement_id)
        
        # Format audit logs
        formatted_audit_logs = []
        for log in audit_logs:
            formatted_log = {
                'action_type': log['action_type'],
                'actor_email': log['actor_email'],
                'timestamp': log['timestamp'],
                'metadata': log['metadata'] if isinstance(log['metadata'], dict) else {}
            }
            formatted_audit_logs.append(formatted_log)
        
        # Get verification status
        verification_data = {
            'valid': True,
            'message': 'Agreement verified successfully',
            'details': {
                'agreement_id': agreement_id,
                'status': agreement['status'],
                'created_at': agreement['created_at'],
                'last_modified': agreement.get('updated_at', agreement['created_at'])
            }
        }
        
        return jsonify({
            'success': True,
            'verification': verification_data,
            'audit_trail': formatted_audit_logs
        })
        
    except Exception as e:
        print(f"Verification error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error verifying agreement: {str(e)}'
        }), 500

@app.route('/api/upload-agreement', methods=['POST'])
def upload_agreement():
    try:
        print("DEBUG - Starting upload_agreement endpoint")
        print(f"DEBUG - Request files: {request.files}")
        print(f"DEBUG - Request form: {request.form}")
        
        if 'pdf_file' not in request.files:
            print("DEBUG - No pdf_file in request.files")
            return jsonify({
                'success': False,
                'message': 'No PDF file uploaded'
            }), 400
            
        pdf_file = request.files['pdf_file']
        print(f"DEBUG - PDF filename: {pdf_file.filename}")
        
        if pdf_file.filename == '':
            print("DEBUG - Empty filename")
            return jsonify({
                'success': False,
                'message': 'No file selected'
            }), 400
            
        if not pdf_file.filename.lower().endswith('.pdf'):
            print(f"DEBUG - Invalid file type: {pdf_file.filename}")
            return jsonify({
                'success': False,
                'message': 'Only PDF files are allowed'
            }), 400
            
        # Verify required form fields
        if 'title' not in request.form or 'recipient_email' not in request.form:
            print("DEBUG - Missing required form fields")
            return jsonify({
                'success': False,
                'message': 'Missing required fields: title and recipient_email'
            }), 400
            
        print("DEBUG - Creating agreement from PDF")
        # Create agreement with uploaded PDF
        agreement = agreement_manager.create_agreement_from_pdf(
            title=request.form['title'],
            recipient_email=request.form['recipient_email'],
            pdf_file=pdf_file,
            client_id=g.user['email'],  # Fix: access email from user dict
            ip_address=get_client_ip()
        )
        
        print(f"DEBUG - Agreement created successfully: {agreement.id}")
        return jsonify({
            'success': True,
            'agreement_id': agreement.id
        })
        
    except Exception as e:
        print(f"DEBUG - Error in upload_agreement: {str(e)}")
        print(f"DEBUG - Error type: {type(e)}")
        import traceback
        print(f"DEBUG - Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400 

@app.route('/api/verify-identity', methods=['POST'])
def verify_identity():
    try:
        data = request.get_json()
        client_ip = get_client_ip()
        
        success, message = agreement_manager.verify_id_and_face(
            agreement_id=data['agreement_id'],
            id_image=data['id_image'],
            selfie_image=data['selfie_image'],
            client_id=data['client_id'],
            ip_address=client_ip
        )
        
        if success:
            # If verification succeeded, the agreement is already signed
            return jsonify({
                'success': True,
                'message': message,
                'agreement_id': data['agreement_id'],
                'signed': True
            })
        
        return jsonify({
            'success': False,
            'message': message
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400 

@app.route('/api/extract-face', methods=['POST'])
def extract_face():
    try:
        print("DEBUG: Starting extract_face endpoint")
        data = request.get_json()
        print(f"DEBUG: Received data keys: {data.keys() if data else 'No data'}")
        
        if not data or 'image' not in data:
            print("DEBUG: No image data in request")
            return jsonify({
                'success': False,
                'message': 'No image data provided'
            }), 400
            
        image_data = data['image']
        print(f"DEBUG: Image data length: {len(image_data) if image_data else 'No image data'}")
        print(f"DEBUG: Image data starts with: {image_data[:50] if image_data else 'No image data'}...")
        
        try:
            # Decode base64 image
            image_bytes = base64.b64decode(image_data.split(',')[1])
            print(f"DEBUG: Decoded image bytes length: {len(image_bytes)}")
        except Exception as e:
            print(f"DEBUG: Error decoding base64 image: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Invalid image data: {str(e)}'
            }), 400
        
        # Extract face using existing face extractor with minimum size requirement
        print("DEBUG: Attempting to extract face")
        face = agreement_manager.face_extractor.extract_face_from_bytes(
            image_bytes,
            min_face_size=(120, 120)  # Increase minimum size to get the main photo
        )
        
        if face is None:
            print("DEBUG: No face detected in image")
            return jsonify({
                'success': False,
                'message': 'No face detected in ID'
            }), 400
        
        print(f"DEBUG: Face extracted successfully, shape: {face.shape}")
        
        # Convert face image back to base64
        _, buffer = cv2.imencode('.jpg', face)
        face_base64 = base64.b64encode(buffer).decode('utf-8')
        print("DEBUG: Successfully converted face back to base64")
        
        return jsonify({
            'success': True,
            'face': f'data:image/jpeg;base64,{face_base64}'
        })
        
    except Exception as e:
        print(f"DEBUG: Unexpected error in extract_face: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400 

# Configure Swagger UI
SWAGGER_URL = '/api/docs'
API_URL = '/static/openapi.yaml'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "E-sign API Documentation",
        'layout': 'BaseLayout',
        'validatorUrl': None
    }
)

# Register blueprint
app.register_blueprint(swaggerui_blueprint)

# Add a direct route to serve the OpenAPI spec
@app.route('/static/openapi.yaml')
def serve_openapi_spec():
    return send_from_directory(
        app.static_folder,
        'openapi.yaml',
        mimetype='text/yaml'
    ) 

@app.route('/api/create-agreement', methods=['POST'])
def create_agreement():
    try:
        print("DEBUG - Starting create_agreement endpoint")
        # Extract data from request
        data = request.get_json()
        if not data:
            print("DEBUG - No JSON data in request")
            return jsonify({
                "success": False,
                "message": "Missing request data"
            }), 400
            
        title = data.get('title')
        content = data.get('content')
        recipient_email = data.get('recipient_email')
        
        print(f"DEBUG - Received request with title: {title}")
        print(f"DEBUG - Content length: {len(content) if content else 0}")
        print(f"DEBUG - Recipient email: {recipient_email}")
        
        # Get client IP for audit log
        ip_address = get_client_ip()
        
        # Get user email from session
        if not g.user or not g.user.get('email'):
            print("DEBUG - No authenticated user found")
            return jsonify({
                "success": False,
                "message": "User not authenticated"
            }), 401
            
        client_id = g.user.get('email')
        
        if not all([title, content, recipient_email, client_id]):
            print(f"DEBUG - Missing required fields: title={bool(title)}, content={bool(content)}, recipient={bool(recipient_email)}, client={bool(client_id)}")
            return jsonify({
                "success": False,
                "message": "Missing required fields"
            }), 400
            
        # Create and send agreement
        print("DEBUG - Calling create_and_send_agreement")
        agreement = agreement_manager.create_and_send_agreement(
            title=title,
            content=content,
            recipient_email=recipient_email,
            client_id=client_id
        )
        
        print(f"DEBUG - Agreement created successfully with ID: {agreement.id}")
        return jsonify({
            "success": True, 
            "agreement_id": agreement.id,
            "message": "Agreement created and sent successfully"
        }), 200
        
    except Exception as e:
        print(f"DEBUG - Error creating agreement: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500 
        
@app.route('/api/resend-agreement/<agreement_id>', methods=['POST'])
def resend_agreement(agreement_id):
    print(f"DEBUG - Resend request received for agreement ID: {agreement_id}")
    try:
        client_ip = get_client_ip()
        
        if not g.user:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401
            
        # Get agreement details
        agreement = agreement_manager.db.get_agreement_details(agreement_id)
        if not agreement:
            return jsonify({
                'success': False,
                'message': 'Agreement not found'
            }), 404
            
        if agreement.get('status') != 'pending':
            return jsonify({
                'success': False,
                'message': f'Cannot resend agreement with status: {agreement.get("status")}'
            }), 400
            
        # Generate transaction ID for this resend operation
        timestamp = datetime.utcnow().timestamp()
        transaction_id = f"tx_{hashlib.sha256(f'{agreement_id}:resend:{timestamp}'.encode()).hexdigest()[:16]}"
        
        # Generate signing URL
        base_url = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")
        signing_url = f"{base_url}/sign/{agreement_id}"
        
        # Generate or retrieve PDF content
        if agreement.get('pdf_source') == 'uploaded' and agreement.get('pdf_path') and os.path.exists(agreement.get('pdf_path')):
            # Use the stored PDF file
            with open(agreement.get('pdf_path'), 'rb') as f:
                pdf_content = BytesIO(f.read())
        else:
            # Generate new PDF from content
            pdf_content = agreement_manager.pdf_generator.generate_agreement_pdf(
                agreement_id=agreement_id,
                title=agreement.get('title', 'Agreement'),
                content=agreement.get('content', ''),
                recipient_email=agreement.get('recipient_email'),
                signing_url=signing_url
            )
        
        # Resend email
        agreement_manager.email_sender.send_agreement_email(
            recipient_email=agreement.get('recipient_email'),
            agreement_id=agreement_id,
            pdf_content=pdf_content,
            signing_url=signing_url
        )
        
        # Log the resend event
        agreement_manager.db.log_audit_event(
            agreement_id=agreement_id,
            action_type='email_resent',
            actor_email=g.user['email'],
            metadata={
                'timestamp': timestamp,
                'transaction_id': transaction_id,
                'recipient_email': agreement.get('recipient_email')
            },
            ip_address=client_ip
        )
        
        return jsonify({
            'success': True,
            'message': f'Agreement email resent successfully to {agreement.get("recipient_email")}',
            'transaction_id': transaction_id
        })
        
    except Exception as e:
        print(f"Error resending agreement: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Error resending agreement: {str(e)}'
        }), 500