import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import os
from dotenv import load_dotenv
from io import BytesIO

class EmailSender:
    def __init__(self):
        """Initialize email sender with SMTP settings from environment"""
        load_dotenv()
        
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_username = os.getenv('SENDER_EMAIL', '')
        self.smtp_password = os.getenv('SENDER_PASSWORD', '')
        self.sender_email = os.getenv('SENDER_EMAIL', self.smtp_username)
        
        # Flag to enable/disable actual email sending (for testing)
        self.send_real_emails = os.getenv('SEND_REAL_EMAILS', 'True').lower() == 'true'
        
        # Print configuration for debugging
        print(f"Email configuration: SMTP={self.smtp_server}:{self.smtp_port}, Username={self.smtp_username}, RealEmails={self.send_real_emails}")
        
    def send_agreement_email(self, recipient_email: str, agreement_id: str, pdf_content: BytesIO, signing_url: str):
        """Send an email with the agreement PDF and signing link"""
        subject = f"Sign Agreement #{agreement_id}"
        body = f"""
        <p>You have been sent an agreement to sign.</p>
        <p>Please click on the link below to view and sign the agreement:</p>
        <p><a href="{signing_url}">{signing_url}</a></p>
        """
        
        # Reset buffer position
        pdf_content.seek(0)
        
        # Create attachment
        attachments = [{
            'filename': f'Agreement_{agreement_id}.pdf',
            'content': pdf_content.read(),
            'content_type': 'application/pdf'
        }]
        
        # Send the email
        self._send_email(recipient_email, subject, body, attachments)
    
    def send_signed_agreement_email(self, recipient_email: str, agreement_id: str, pdf_content: BytesIO, signature: str, transaction_id: str = None):
        """Send an email with the signed agreement PDF"""
        subject = f"Signed Agreement #{agreement_id}"
        body = f"""
        <p>The agreement has been successfully signed.</p>
        <p>The signed agreement is attached to this email.</p>
        <p>Digital Signature: {signature[:20]}...</p>
        <p>Transaction ID: {transaction_id or 'N/A'}</p>
        """
        
        # Reset buffer position
        pdf_content.seek(0)
        
        # Create attachment
        attachments = [{
            'filename': f'Signed_Agreement_{agreement_id}.pdf',
            'content': pdf_content.read(),
            'content_type': 'application/pdf'
        }]
        
        # Send the email
        self._send_email(recipient_email, subject, body, attachments)
    
    def _send_email(self, recipient_email: str, subject: str, body: str, attachments=None):
        """Send an email using SMTP"""
        # Always print debug info
        print(f"Sending email to {recipient_email}")
        print(f"Subject: {subject}")
        
        # If not configured to send real emails, just log it
        if not self.send_real_emails or not self.smtp_username or not self.smtp_password:
            print(f"Email sending disabled or credentials missing. SMTP Username: {self.smtp_username if self.smtp_username else 'MISSING'}")
            print(f"SMTP Password: {'SET' if self.smtp_password else 'MISSING'}")
            print(f"Would send email to {recipient_email}")
            print(f"Email body: {body}")
            if attachments:
                for attachment in attachments:
                    print(f"Attachment: {attachment['filename']}, size: {len(attachment['content'])} bytes")
            return
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = subject
            
            # Add body
            msg.attach(MIMEText(body, 'html'))
            
            # Add attachments
            if attachments:
                for attachment in attachments:
                    part = MIMEApplication(attachment['content'])
                    part.add_header('Content-Disposition', 'attachment', 
                                    filename=attachment['filename'])
                    msg.attach(part)
            
            print(f"Connecting to SMTP server {self.smtp_server}:{self.smtp_port}")
            print(f"Logging in with username: {self.smtp_username}")
            
            # Connect to SMTP server and send
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
                
            print(f"Email sent successfully to {recipient_email}")
            
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
            import traceback
            traceback.print_exc()

    def send_signed_notification(self, agreement_id: str, recipient_email: str):
        """Send a notification email when an agreement is signed (without PDF attachment)"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = f"Agreement {agreement_id} has been signed"
            
            body = f"""
            The agreement {agreement_id} has been successfully signed.
            
            You can view the signed agreement in your dashboard.
            """
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email with proper TLS setup
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.ehlo()  # Identify ourselves to the server
                if server.has_extn('STARTTLS'):  # Check if TLS is supported
                    server.starttls()  # Enable encryption
                    server.ehlo()  # Re-identify ourselves over TLS connection
                
                # Now try to login
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
                
        except Exception as e:
            print(f"Email error: {str(e)}")  # Add better error logging
            # Don't raise the exception for notifications - just log it
            return False
        
        return True 