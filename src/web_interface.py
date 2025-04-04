from flask import Flask, render_template, request, jsonify, session, g
from src.agreement_manager import AgreementManager
import os
from dotenv import load_dotenv
import base64
from datetime import datetime, timedelta
from src.utils.tls_config import TLSConfig
from src.utils.session_manager import SessionManager
from flask_wtf.csrf import CSRFProtect
from flask import redirect, url_for
from functools import wraps
from src.face_utils import FaceExtractor
import secrets
from flask import Response
import google.generativeai as genai
from google.generativeai import GenerativeModel
from src.utils.gemini_chat import GeminiChat
import werkzeug.exceptions
import cv2
import json

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
)
load_dotenv()

SIGNING_BASE_URL = os.getenv("SIGNING_BASE_URL", "http://localhost:5000")
# Get the directory where web_interface.py is located
base_dir = os.path.dirname(os.path.abspath(__file__))
blockchain_path = os.path.join(base_dir, "..", "data", "blockchain.json")

print(f"Initializing agreement manager with blockchain at: {blockchain_path}")
agreement_manager = AgreementManager(blockchain_path=blockchain_path)

# Add after agreement manager initialization
face_extractor = FaceExtractor()

# Add after app initialization
tls_config = TLSConfig()
ssl_context = tls_config.get_ssl_context()

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
    agreements = [t['agreement_id'] for b in agreement_manager.blockchain.chain for t in b.transactions]
    return jsonify({
        'status': 'healthy',
        'message': 'Service is running',
        'agreements': agreements
    })

@app.route('/sign/<agreement_id>')
def sign_page(agreement_id):
    # Get agreement details from blockchain
    agreement_data = agreement_manager.blockchain.get_agreement(agreement_id)
    
    if not agreement_data:
        return f"Agreement {agreement_id} not found.", 404
    
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
        
        # Handle both FormData and JSON requests
        if request.content_type and 'multipart/form-data' in request.content_type:
            agreement_id = request.form.get('agreement_id')
            client_id = request.form.get('client_id')
            image_file = request.files.get('image')
        else:
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'message': 'No data received'
                }), 400
            
            agreement_id = data.get('agreement_id')
            client_id = data.get('client_id')
            image_data = data.get('image')
        
        # Check if agreement is already signed
        agreement = agreement_manager.db.get_agreement_details(agreement_id)
        if not agreement:
            return jsonify({
                'success': False,
                'message': 'Agreement not found'
            }), 404
            
        if agreement.get('status') == 'signed':
            return jsonify({
                'success': False,
                'message': 'Agreement has already been signed'
            }), 400
            
        # Continue with existing signature processing...
        success, message = agreement_manager.process_signature(
            agreement_id=agreement_id,
            client_id=client_id,
            image_data=image_data,
            ip_address=client_ip
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': message,
                'agreement_id': agreement_id
            })
            
        return jsonify({
            'success': False,
            'message': message
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
        
        # Create agreement with IP logging
        agreement = agreement_manager.create_agreement(
            title=data.get('title', 'Untitled Agreement'),
            content=data.get('content', ''),
            recipient_email=data.get('recipient_email'),
            client_id=g.user['email'],
            ip_address=client_ip
        )
        
        # Log agreement creation in audit trail
        agreement_manager.db.log_audit_event(
            agreement_id=agreement.id,
            action_type='created',
            actor_email=g.user['email'],
            metadata={
                'title': data.get('title', 'Untitled Agreement'),
                'recipient_email': data.get('recipient_email'),
                'timestamp': datetime.now().isoformat()
            },
            ip_address=client_ip
        )
        
        return jsonify({
            'success': True,
            'agreement_id': agreement.id,
            'message': 'Agreement created successfully'
        })
        
    except Exception as e:
        print(f"DEBUG - Error creating contract: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/create-contract')
def create_contract_page():
    """Create contract page"""
    return render_template('create_contract.html')

@app.route('/api/cancel-agreement/<agreement_id>', methods=['POST'])
def cancel_agreement(agreement_id):
    """Cancel an agreement"""
    try:
        client_id = request.json.get('client_id')
        if not client_id:
            return jsonify({'error': 'client_id required'}), 400
            
        # Get client IP using helper function
        client_ip = get_client_ip()
            
        success, message = agreement_manager.cancel_agreement(
            agreement_id=agreement_id, 
            client_id=client_id,
            ip_address=client_ip  # Pass the IP address
        )
        
        if success:
            return jsonify({'message': message})
        else:
            return jsonify({'error': message}), 400
            
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
        audit_logs = agreement_manager.db.get_agreement_audit_trail(agreement_id)
        return jsonify(audit_logs)
    except Exception as e:
        print(f"Error fetching audit logs: {str(e)}")
        return jsonify({
            'error': 'Failed to fetch audit logs'
        }), 500 

@app.after_request
def add_security_headers(response):
    """Add security headers to every response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# First define the decorators
# def rate_limit(key_prefix: str = None, max_requests: int = 10, window: int = 60):
#     """Rate limiting decorator with configurable parameters
    
#     Args:
#         key_prefix (str): Prefix for rate limit key
#         max_requests (int): Maximum number of requests allowed in window
#         window (int): Time window in seconds
#     """
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             # Get client IP
#             client_ip = request.remote_addr
            
#             # Create rate limit key (combine prefix with IP or user identifier)
#             key = f"{key_prefix}:{client_ip}" if key_prefix else client_ip
            
#             # Check rate limit with custom parameters
#             is_limited, remaining, retry_after = app.rate_limiter.is_rate_limited(
#                 key, 
#                 max_requests=max_requests,
#                 window=window
#             )
            
#             if is_limited:
#                 # Check if client accepts JSON
#                 accepts_json = request.headers.get('Accept', '').find('application/json') != -1
#                 return app.rate_limiter.get_rate_limit_response(
#                     is_limited=True,
#                     remaining=remaining,
#                     retry_after=retry_after,
#                     accepts_json=accepts_json
#                 )
            
#             # Add rate limit headers
#             response = f(*args, **kwargs)
#             if isinstance(response, tuple):
#                 response, status_code = response
#             else:
#                 status_code = 200
                
#             # Convert response to Response object if it's not already
#             if not isinstance(response, Response):
#                 response = jsonify(response)
                
#             response.headers['X-RateLimit-Remaining'] = str(remaining)
#             response.headers['X-RateLimit-Reset'] = str(int(time.time() + retry_after))
#             return response, status_code
            
#         return decorated_function
#     return decorator

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

# Add after other environment variable initializations
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = GenerativeModel('gemini-2.0-flash')

# Add after genai.configure
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    print("Warning: GEMINI_API_KEY not found in environment variables")
else:
    print(f"Gemini API key loaded: {api_key[:5]}...")  # Only print first 5 chars for security

# Add after app initialization
gemini_chat = GeminiChat()

# Replace the existing generate_contract_ai route
@app.route('/api/generate-contract', methods=['POST'])
@csrf.exempt
def generate_contract_ai():
    try:
        data = request.get_json()
        prompt = data.get('prompt')
        
        if not prompt:
            return jsonify({
                'success': False,
                'message': 'No prompt provided'
            }), 400

        # Use session ID to maintain chat history
        session_id = session.get('session_token')
        
        # Generate contract using chat history
        result = gemini_chat.generate_contract(prompt, session_id)
        
        return jsonify(result)

    except Exception as e:
        print(f"Error generating contract: {str(e)}")  # Debug log
        return jsonify({
            'success': False,
            'message': f'Error generating contract: {str(e)}'
        }), 500

# Add route to clear chat history when needed
@app.route('/api/clear-chat', methods=['POST'])
@csrf.exempt
def clear_chat_history():
    session_id = session.get('session_token')
    if session_id:
        gemini_chat.clear_chat_history(session_id)
    return jsonify({'success': True})

# Modify the run statement at the bottom of the file
if __name__ == '__main__':
    app.run(ssl_context=ssl_context, host='0.0.0.0', port=5000) 

@app.route('/api/agreements', methods=['POST'])
def create_agreement():
    try:
        data = request.get_json()
        client_ip = get_client_ip()

        agreement = agreement_manager.create_agreement(
            title=data['title'],
            content=data['content'],
            recipient_email=data['recipient_email'],
            client_id=g.user.email,
            ip_address=client_ip
        )
        
        return jsonify({
            'success': True,
            'agreement_id': agreement.id
        })
    except Exception as e:
        print(f"DEBUG - Error in create_agreement: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400 

@app.route('/verify')
def verify_page():
    """Public verification page where users can enter their email to view their agreements"""
    return render_template('verify.html')

@app.route('/api/verify/agreements', methods=['POST'])
@csrf.exempt  # Allow public access without CSRF
# @rate_limit('verify_agreements')  # Add rate limiting for security
def verify_agreements():
    """Public endpoint to fetch agreements associated with an email"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({
                'success': False,
                'message': 'Email is required'
            }), 400

        # Get all agreements associated with the email
        response = agreement_manager.db.supabase.table('agreement_details') \
            .select('*') \
            .eq('recipient_email', email) \
            .execute()
            
        agreements = []
        for agreement in response.data:
            agreements.append({
                'id': agreement['agreement_id'],
                'title': agreement['title'],
                'status': agreement['status'],
                'created_at': agreement['created_at'],
                'recipient_email': agreement['recipient_email'],
                'created_by': agreement.get('created_by')
            })
        
        return jsonify({
            'success': True,
            'agreements': agreements
        })

    except Exception as e:
        print(f"Error fetching agreements for verification: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch agreements'
        }), 500

@app.route('/api/verify/blockchain/<agreement_id>')
def verify_blockchain(agreement_id):
    try:
        verification_data = agreement_manager.blockchain.verify_agreement(agreement_id)
        
        # Get blocks related to this agreement
        blocks = agreement_manager.blockchain.db.get_blocks()
        filtered_blocks = []
        
        for block in blocks:
            if isinstance(block['transactions'], str):
                try:
                    block['transactions'] = json.loads(block['transactions'])
                except json.JSONDecodeError:
                    block['transactions'] = []
            
            for tx in block['transactions']:
                if tx.get('agreement_id') == agreement_id:
                    filtered_blocks.append({
                        'index': block['index'],
                        'hash': block['hash'],
                        'timestamp': block['timestamp'],
                        'transaction': {
                            'type': tx.get('type', 'creation'),
                            'timestamp': tx.get('timestamp'),
                            'id': tx.get('id'),
                            'agreement_id': tx.get('agreement_id'),
                            'recipient_email': tx.get('recipient_email')
                        }
                    })
                    break
        
        # Get audit logs for this agreement
        audit_logs = agreement_manager.db.get_agreement_audit_trail(agreement_id)
        
        # Format audit logs to match UI expectations
        formatted_audit_logs = []
        for log in audit_logs:
            formatted_log = {
                'action_type': log['action_type'],
                'actor_email': log['actor_email'],
                'timestamp': log['timestamp'],
                'metadata': log['metadata'] if isinstance(log['metadata'], dict) else {}
            }
            formatted_audit_logs.append(formatted_log)
        
        return jsonify({
            'success': True,
            'verification': verification_data,
            'blockchain_valid': verification_data['is_valid'],
            'database_consistent': verification_data['database_consistency']['is_valid'],
            'details': {
                'blockchain': verification_data['details'],
                'database': verification_data['database_consistency']['details']
            },
            'blockchain_evolution': filtered_blocks,
            'audit_trail': formatted_audit_logs
        })
    except Exception as e:
        print(f"Verification error: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
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