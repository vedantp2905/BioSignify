from flask import Flask, render_template, request, jsonify, session, g, flash, send_file, Response
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
from src.email_sender import EmailSender
import io

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
    public_endpoints = [
        'login', 
        'static', 
        'health_check', 
        'home',  # This is the root route '/'
        'organization_signup_page',
        'organization_signup',
        'serve_openapi_spec',
        'sign_page'  # Allow direct access to signing page
    ]
    
    # Skip authentication for public endpoints
    if request.endpoint in public_endpoints:
        return None  # Important: return None to continue processing
    
    # Skip auth check for static files
    if request.path.startswith('/static/'):
        return None
        
    # Validate session for protected routes
    token = session.get('session_token')
    if not token:
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized'}), 401
        return redirect(url_for('home'))  # Changed from 'login' to 'home'
    
    user_data = app.session_manager.validate_session(token)
    if not user_data:
        session.clear()
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Session expired'}), 401
        return redirect(url_for('home'))  # Changed from 'login' to 'home'
    
    g.user = user_data

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

def require_org_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or not g.user.get('organization_id'):
            return jsonify({
                'error': 'Unauthorized',
                'message': 'No organization access'
            }), 403
        return f(*args, **kwargs)
    return decorated_function

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
            
        # Process signature with correct parameters
        success = agreement_manager.process_signature(
            agreement_id=agreement_id,
            signature_data={
                'client_id': client_id,
                'ip_address': client_ip
            }
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Agreement signed successfully. Signed copies have been sent to all parties.',
                'agreement_id': agreement_id
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
    """Landing page with signup/login options"""
    # Check if user is already logged in
    token = session.get('session_token')
    if token:
        user_data = app.session_manager.validate_session(token)
        if user_data and user_data.get('organization_id'):
            return redirect(url_for('dashboard'))
    
    # If not logged in, show the home page with signup/login options
    return render_template('home.html')

@app.route('/pending-agreements')
@require_auth
def pending_agreements():
    """Pending agreements page"""
    return render_template('pending_agreements.html')

@app.route('/api/pending-agreements')
@require_auth
def get_pending_agreements():
    try:
        # Filter by organization
        response = agreement_manager.db.supabase.table('agreement_details') \
            .select('*') \
            .eq('status', 'pending') \
            .eq('organization_id', g.user['organization_id']) \
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
@require_auth
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
@require_auth
def signed_agreements_page():
    """Signed agreements page"""
    return render_template('signed_agreements.html')

@app.route('/cancelled-agreements')
@require_auth
def cancelled_agreements():
    """Display cancelled agreements for the organization"""
    try:
        # Get cancelled agreements for the organization
        agreements = agreement_manager.db.get_organization_agreements(
            organization_id=g.user['organization_id'],
            status='cancelled'
        )
        
        return render_template(
            'cancelled_agreements.html',
            agreements=agreements,
            user=g.user
        )
    except Exception as e:
        print(f"Error loading cancelled agreements: {str(e)}")
        return render_template('error.html', 
            message=f"Error loading cancelled agreements: {str(e)}"
        )

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

# Then define your routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
        
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({
                'error': 'Bad request',
                'message': 'Email and password are required'
            }), 400
        
        # Hash the password for comparison
        password_hash = hashlib.sha256(password.encode()).hexdigest()
            
        # Get user's organizations and verify password
        user = agreement_manager.db.verify_user_credentials(email, password_hash)
        if not user:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid email or password'
            }), 401
            
        # Create session with organization context
        token = app.session_manager.create_session(
            user_id=email,
            email=email,
            organization_id=user['organization_id'],
            role=user['role']
        )
        
        session['session_token'] = token
        return jsonify({
            'success': True,
            'redirect': url_for('dashboard')
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Server error',
            'message': str(e)
        }), 500

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
        
        if not g.user:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Get organization details to use organization email as sender
        organization = agreement_manager.db.get_organization(g.user['organization_id'])
        if not organization or not organization.get('email'):
            return jsonify({
                'success': False,
                'message': 'Organization email not configured'
            }), 400
        
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
            client_id=g.user['email'],
            sender_email=organization['email'],  # Add the organization email as sender
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
@require_auth
@require_org_auth
def create_agreement():
    try:
        data = request.get_json()
        
        # Create agreement with organization context
        agreement = agreement_manager.create_and_send_agreement(
            title=data.get('title'),
            content=data.get('content'),
            recipient_email=data.get('recipient_email'),
            client_id=g.user['email'],
            organization_id=g.user['organization_id']
        )
        
        return jsonify({
            "success": True, 
            "agreement_id": agreement.id,
            "message": "Agreement created and sent successfully"
        })
        
    except Exception as e:
            return jsonify({
                "success": False,
            "message": str(e)
        }), 500

@app.route('/api/resend-agreement/<agreement_id>', methods=['POST'])
def resend_agreement(agreement_id):
    try:
        # Get agreement details
        agreement = agreement_manager.db.get_agreement_details(agreement_id)
        if not agreement:
            return jsonify({'error': 'Agreement not found'}), 404

        # Get organization details
        organization = agreement_manager.db.get_organization(agreement['organization_id'])
        if not organization:
            return jsonify({'error': 'Organization not found'}), 404

        # Get organization email settings
        sender_email = organization.get('email')
        smtp_password = organization.get('smtp_password')
        smtp_server = organization.get('smtp_server')
        smtp_port = organization.get('smtp_port')

        if not all([sender_email, smtp_password, smtp_server, smtp_port]):
            return jsonify({'error': 'Organization email settings not configured'}), 400

        # Generate signing URL
        base_url = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")
        signing_url = f"{base_url}/sign/{agreement_id}"

        # Read the PDF file
        pdf_content = BytesIO()
        with open(agreement['pdf_path'], 'rb') as f:
            pdf_content.write(f.read())
        pdf_content.seek(0)

        # Send the email
        success = agreement_manager.email_sender.send_agreement_email(
            recipient_email=agreement['recipient_email'],
            agreement_id=agreement_id,
            pdf_content=pdf_content,
            signing_url=signing_url,
            sender_email=sender_email,
            smtp_password=smtp_password,
            smtp_server=smtp_server,
            smtp_port=smtp_port
        )

        if success:
            return jsonify({'message': 'Agreement resent successfully'}), 200
        else:
            return jsonify({'error': 'Failed to resend agreement'}), 500

    except Exception as e:
        print(f"Error resending agreement: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/organizations/signup', methods=['GET'])
def organization_signup_page():
    """Organization signup page"""
    return render_template('organization_signup.html')

@app.route('/api/organizations/signup', methods=['POST'])
@csrf.exempt
def organization_signup():
    """API endpoint for organization signup"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'adminEmail', 'adminPassword']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'Missing required field: {field}'
            }), 400
            
        # Validate password length
        if len(data['adminPassword']) < 8:
            return jsonify({
                'success': False,
                'message': 'Password must be at least 8 characters long'
            }), 400

        # Hash the password
        password_hash = hashlib.sha256(data['adminPassword'].encode()).hexdigest()

        # Create organization
        org = agreement_manager.db.create_organization(
            name=data['name'],
            email=data['email']
        )
        
        if not org:
            return jsonify({
                'success': False,
                'message': 'Failed to create organization'
            }), 500

        # Add admin user with password
        user = agreement_manager.db.add_organization_user(
            organization_id=org['id'],
            email=data['adminEmail'],
            role='admin',
            password_hash=password_hash
        )
        
        if not user:
            # Rollback organization creation if possible
            return jsonify({
                'success': False,
                'message': 'Failed to create admin user'
            }), 500

        return jsonify({
            'success': True,
            'message': 'Organization created successfully'
        })
        
    except Exception as e:
        print(f"Error in organization signup: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
            }), 400
            
@app.route('/api/organizations/<org_id>/agreements')
@require_auth
@require_org_auth
def get_organization_agreements(org_id):
    """Get agreements for an organization"""
    try:
        # Verify user belongs to organization
        if g.user['organization_id'] != org_id:
            return jsonify({
                'success': False,
                'message': 'Unauthorized'
            }), 403
            
        status = request.args.get('status')
        agreements = agreement_manager.db.get_organization_agreements(org_id, status)
        
        return jsonify({
            'success': True,
            'agreements': agreements
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500 
        
@app.route('/organization/settings')
@require_auth
@require_org_auth
def organization_settings():
    """Organization settings page"""
    try:
        org_id = g.user['organization_id']
        organization = agreement_manager.db.get_organization(org_id)
        
        if not organization:
            return render_template('error.html', 
                message="Organization not found. Please contact support.")
        
        # Add any additional organization settings from the database
        organization = {
            'id': organization.get('id'),
            'name': organization.get('name'),
            'email': organization.get('email'),
            'email_signature': organization.get('email_signature'),
            'logo_url': organization.get('logo_url'),
            'primary_color': organization.get('primary_color'),
            'created_at': organization.get('created_at')
        }
        
        return render_template('organization_settings.html', 
                             organization=organization,
                             user=g.user)
    except Exception as e:
        print(f"Error loading organization settings: {str(e)}")
        return render_template('error.html', 
            message="Error loading organization settings. Please try again later.")

@app.route('/organization/users')
@require_auth
@require_org_auth
def organization_users():
    """Organization users management page"""
    try:
        org_id = g.user['organization_id']
        if g.user['role'] != 'admin':
            return render_template('error.html', message="Unauthorized")
            
        organization = agreement_manager.db.get_organization(org_id)
        users = agreement_manager.db.get_organization_users(org_id)
        return render_template('organization_users.html', 
                             organization=organization,
                             organization_users=users)
    except Exception as e:
        return render_template('error.html', message=str(e))

@app.route('/api/organization/users', methods=['POST'])
@require_auth
@require_org_auth
@csrf.exempt  # Add this decorator since we'll handle CSRF manually
def add_organization_user():
    """Add a new user to the organization"""
    try:
        if g.user['role'] != 'admin':
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
            
        data = request.get_json()
        email = data['email']
        role = data.get('role', 'user')
        
        # Create user with pending status
        try:
            user = agreement_manager.db.add_organization_user(
                organization_id=g.user['organization_id'],
                email=email,
                role=role,
                status='pending'  # This will now be accepted by the method
            )
            
            if not user:
                raise Exception("Failed to create user record")
                
            # Create invitation token
            token = agreement_manager.db.create_invitation_token(email, g.user['organization_id'])
            
            # Generate setup URL
            setup_url = url_for('setup_invitation', token=token, _external=True)
            
            # Send invitation email using EmailSender
            email_body = render_template('email/invitation.html',
                setup_url=setup_url,
                organization_name=g.user.get('organization_name', 'BioSign')
            )
            
            # Send invitation email
            email_sent = email_sender.send_email(
                recipient_email=email,
                subject='Complete your BioSign account setup',
                body=email_body,
                is_html=True
            )
            
            if not email_sent:
                raise Exception("Failed to send invitation email")
            
            return jsonify({
                'success': True,
                'message': f'Invitation sent to {email}'
            })
            
        except Exception as e:
            print(f"Error in user creation process: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Failed to create user: {str(e)}'
            }), 400
            
    except Exception as e:
        print(f"Error adding user: {str(e)}")
        return jsonify({
                'success': False,
            'message': str(e)
        }), 400

@app.route('/setup-invitation/<token>')
def setup_invitation(token):
    """Handle invitation setup page"""
    try:
        invitation = agreement_manager.db.verify_invitation_token(token)
        if not invitation:
            return render_template('error.html',
                message='Invalid or expired invitation link'
            )
        
        return render_template('setup_invitation.html',
            token=token,
            email=invitation['email']
        )
    except Exception as e:
        print(f"Error in setup_invitation: {str(e)}")
        return render_template('error.html',
            message='Error processing invitation'
        )

@app.route('/api/users/complete-setup', methods=['POST'])
def complete_setup():
    """Complete user setup from invitation"""
    try:
        data = request.get_json()
        token = data['token']
        name = data['name']
        password = data['password']
        
        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        success = agreement_manager.db.complete_user_setup(
            token=token,
            name=name,
            password_hash=password_hash
        )
        
        if not success:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired invitation'
            }), 400
            
        return jsonify({
            'success': True,
            'message': 'Account setup completed successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400

@app.route('/dashboard')
@require_auth
def dashboard():
    """Organization dashboard page"""
    try:
        org_id = g.user.get('organization_id')
        if not org_id:
            return redirect(url_for('home'))
            
        organization = agreement_manager.db.get_organization(org_id)
        if not organization:
            session.clear()
            return redirect(url_for('home'))
        
        # Get statistics
        stats = {
            'total': 0,
            'pending': 0,
            'signed': 0,
            'cancelled': 0,
            'this_month': 0
        }
        
        # Get recent activities and agreements
        agreements = agreement_manager.db.get_organization_agreements(org_id) or []
        recent_activities = []
        
        for agreement in agreements[:5]:  # Last 5 agreements
            status_class = {
                'pending': 'warning',
                'signed': 'success',
                'cancelled': 'danger'
            }.get(agreement['status'], 'secondary')
            
            recent_activities.append({
                'id': agreement['agreement_id'],
                'title': agreement['title'],
                'recipient_email': agreement['recipient_email'],
                'status': agreement['status'],
                'status_class': status_class,
                'date': agreement['created_at']
            })
            
            # Update stats
            stats['total'] += 1
            if agreement['status'] == 'pending':
                stats['pending'] += 1
            elif agreement['status'] == 'signed':
                stats['signed'] += 1
            elif agreement['status'] == 'cancelled':
                stats['cancelled'] += 1
                
            # Check if created this month
            created_at = datetime.fromisoformat(agreement['created_at'].replace('Z', '+00:00'))
            if created_at.month == datetime.now().month and created_at.year == datetime.now().year:
                stats['this_month'] += 1
        
        return render_template('organization_dashboard.html',
                             organization=organization,
                             stats=stats,
                             recent_activities=recent_activities,
                             user_role=g.user.get('role', 'user'))
    except Exception as e:
        print(f"Error loading dashboard: {str(e)}")
        return render_template('error.html', message="Error loading dashboard")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Add with other initializations
email_sender = EmailSender()

# Add this right after creating the Flask app, before any routes
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return value
    return value.strftime('%Y-%m-%d %H:%M:%S')

app.jinja_env.filters['datetime'] = format_datetime

@app.route('/api/organization/settings/email', methods=['POST'])
@require_auth
@require_org_auth
def update_organization_email_settings():
    """Update organization email settings"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'smtp_password', 'smtp_server', 'smtp_port']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'Missing required field: {field}'
                }), 400
        
        # Validate port number
        try:
            smtp_port = int(data['smtp_port'])
            if smtp_port <= 0 or smtp_port > 65535:
                raise ValueError()
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Invalid SMTP port number'
            }), 400
        
        # Update organization settings
        updated_org = agreement_manager.db.update_organization_email_settings(
            org_id=g.user['organization_id'],
            email_settings={
                'email': data['email'],
                'smtp_password': data['smtp_password'],
                'smtp_server': data['smtp_server'],
                'smtp_port': smtp_port
            }
        )
        
        if not updated_org:
            return jsonify({
                'success': False,
                'message': 'Failed to update email settings'
            }), 500
        
        return jsonify({
            'success': True,
            'message': 'Email settings updated successfully'
        })
        
    except Exception as e:
        print(f"Error updating email settings: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400

@app.route('/api/organization/settings/test-email', methods=['POST'])
@require_auth
@require_org_auth
def test_organization_email():
    """Send a test email using organization's email settings"""
    try:
        data = request.get_json()
        test_email = data.get('test_email')
        
        if not test_email:
            return jsonify({
                'success': False,
                'message': 'Test email address is required'
            }), 400
        
        # Get organization details
        organization = agreement_manager.db.get_organization(g.user['organization_id'])
        if not organization:
            return jsonify({
                'success': False,
                'message': 'Organization not found'
            }), 404
            
        # Validate SMTP settings
        if not organization.get('smtp_server') or not organization.get('smtp_port') or not organization.get('smtp_password'):
            return jsonify({
                'success': False,
                'message': 'Organization email settings are not fully configured'
            }), 400
        
        # Configure email sender with organization's SMTP settings
        email_sender.configure_smtp(
            smtp_server=organization['smtp_server'],
            smtp_port=organization['smtp_port'],
            smtp_password=organization['smtp_password']
        )
        
        # Send test email
        success = email_sender.send_email(
            recipient_email=test_email,
            subject='Test Email from BioSign',
            body=f'''
            <h2>Test Email</h2>
            <p>This is a test email to verify your email configuration.</p>
            <p>If you received this email, your email settings are configured correctly.</p>
            <p>Organization: {organization['name']}</p>
            <p>Sender Email: {organization['email']}</p>
            ''',
            sender_email=organization['email'],
            is_html=True
        )
        
        if success:
            return jsonify({
            'success': True,
                'message': f'Test email sent successfully to {test_email}'
        })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send test email. Please check your email settings.'
            }), 500
        
    except Exception as e:
        print(f"Error sending test email: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error sending test email: {str(e)}'
        }), 400

@app.route('/api/agreements/<agreement_id>/signed-pdf', methods=['GET'])
def get_signed_pdf(agreement_id):
    try:
        pdf_content = agreement_manager.get_signed_pdf(agreement_id)
        if not pdf_content:
            return jsonify({'error': 'Signed PDF not found'}), 404
            
        # Check if download is requested
        download = request.args.get('download', 'false').lower() == 'true'
        
        filename = f"signed_agreement_{agreement_id}.pdf"
        mimetype = 'application/pdf'
        
        if download:
            return send_file(
                io.BytesIO(pdf_content),
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )
        else:
            # Display in browser
            return Response(pdf_content, mimetype=mimetype)
            
    except Exception as e:
        print(f"Error retrieving signed PDF: {str(e)}")
        return jsonify({'error': 'Failed to retrieve signed PDF'}), 500