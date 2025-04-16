import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import os
from io import BytesIO
from flask import render_template
from typing import List, Tuple
from datetime import datetime

class EmailSender:
    def __init__(self):

        # Default SMTP settings (can be overridden per organization)
        self.default_smtp_server = os.getenv('DEFAULT_SMTP_SERVER', 'smtp.office365.com')
        self.default_smtp_port = int(os.getenv('DEFAULT_SMTP_PORT', '587'))
        self.smtp_use_tls = True
        self.smtp_use_ssl = False
        
        # Flag for testing
        self.send_real_emails = os.getenv('SEND_REAL_EMAILS', 'True').lower() == 'true'
        
        # Organization-specific settings
        self.org_smtp_server = None
        self.org_smtp_port = None
        self.org_smtp_password = None

    def configure_smtp(self, smtp_server: str, smtp_port: int, smtp_password: str):
        """Configure SMTP settings for an organization"""
        self.org_smtp_server = smtp_server
        self.org_smtp_port = smtp_port
        self.org_smtp_password = smtp_password

    def _get_smtp_connection(self, smtp_server, smtp_port):
        """Get appropriate SMTP connection based on configuration"""
        if self.smtp_use_ssl:
            return smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            return smtplib.SMTP(smtp_server, smtp_port)

    def send_agreement_email(self, recipient_email: str, agreement_id: str, 
                           pdf_content: BytesIO, signing_url: str, sender_email: str,
                           smtp_password: str = None, smtp_server: str = None, 
                           smtp_port: int = None) -> bool:
        """Send agreement email with PDF attachment using organization's email settings"""
        try:
            print("=== Email Sending Debug Info ===")
            print(f"send_real_emails flag: {self.send_real_emails}")
            print(f"SMTP Server: {smtp_server}")
            print(f"SMTP Port: {smtp_port}")
            print(f"Sender Email: {sender_email}")
            print(f"Recipient Email: {recipient_email}")
            print(f"Has SMTP Password: {'Yes' if smtp_password else 'No'}")
            print("=============================")
            
            print(f"Sending agreement email:")
            print(f"- To: {recipient_email}")
            print(f"- From: {sender_email}")
            print(f"- Agreement ID: {agreement_id}")
            
            # Use provided SMTP settings or defaults
            smtp_server = smtp_server or self.default_smtp_server
            smtp_port = smtp_port or self.default_smtp_port
            
            if not smtp_password:
                print("ERROR: SMTP password not provided for organization email")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['Subject'] = 'New Agreement for Signature'
            msg['From'] = sender_email
            msg['To'] = recipient_email
            
            # Add body
            body = render_template('email/agreement.html',
                signing_url=signing_url
            )
            msg.attach(MIMEText(body, 'html'))
            
            # Add PDF attachment
            pdf_content.seek(0)
            pdf_attachment = MIMEApplication(pdf_content.getvalue(), _subtype='pdf')
            pdf_attachment.add_header('Content-Disposition', 'attachment', 
                                    filename=f'agreement_{agreement_id}.pdf')
            msg.attach(pdf_attachment)
            
            # Send email using organization's SMTP settings
            if not self.send_real_emails:
                print("Email sending disabled - would have sent email")
                return True
            
            with self._get_smtp_connection(smtp_server, smtp_port) as server:
                print(f"Connecting to SMTP server {smtp_server}:{smtp_port}...")
                if self.smtp_use_tls and not self.smtp_use_ssl:
                    server.starttls()
                    print("TLS encryption enabled")
                print(f"Logging in as {sender_email}...")
                server.login(sender_email, smtp_password)
                print("Sending email...")
                server.send_message(msg)
                print("Email sent successfully!")
                return True
            
        except Exception as e:
            print(f"ERROR sending agreement email: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_signed_agreement_email(self, recipient_email: str, agreement_id: str, 
                                  pdf_content: BytesIO, signature: str, 
                                  transaction_id: str = None, sender_email: str = None):
        """Send an email with the signed agreement PDF"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['Subject'] = f"Signed Agreement #{agreement_id}"
            msg['To'] = recipient_email
            msg['From'] = sender_email  # Use provided sender_email
            
            # Add HTML body using template
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            body = render_template('email/signed_agreement.html',
                agreement_id=agreement_id,
                transaction_id=transaction_id or 'N/A',
                timestamp=timestamp,
                signature=signature
            )
            msg.attach(MIMEText(body, 'html'))
            
            # Reset buffer position and attach PDF
            pdf_content.seek(0)
            pdf_attachment = MIMEApplication(pdf_content.read(), _subtype='pdf')
            pdf_attachment.add_header('Content-Disposition', 'attachment', 
                                    filename=f'Signed_Agreement_{agreement_id}.pdf')
            msg.attach(pdf_attachment)
            
            if not self.send_real_emails:
                print(f"Email sending disabled - would have sent signed agreement to {recipient_email}")
                return True
            
            # Send email using configured SMTP settings
            with self._get_smtp_connection(self.org_smtp_server, self.org_smtp_port) as server:
                if self.smtp_use_tls and not self.smtp_use_ssl:
                    server.starttls()
                print(f"Sending signed agreement email from {sender_email} to {recipient_email}")
                server.login(sender_email, self.org_smtp_password)
                server.send_message(msg)
                
            print(f"Signed agreement sent successfully to {recipient_email}")
            return True
            
        except Exception as e:
            print(f"Error sending signed agreement email: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_signed_notification(self, agreement_id: str, recipient_email: str):
        """Send a notification email when an agreement is signed (without PDF attachment)"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.default_smtp_server
            msg['To'] = recipient_email
            msg['Subject'] = f"Agreement {agreement_id} has been signed"
            
            body = f"""
            The agreement {agreement_id} has been successfully signed.
            
            You can view the signed agreement in your dashboard.
            """
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email with proper TLS setup
            with self._get_smtp_connection(self.default_smtp_server, self.default_smtp_port) as server:
                server.ehlo()  # Identify ourselves to the server
                if server.has_extn('STARTTLS'):  # Check if TLS is supported
                    server.starttls()  # Enable encryption
                    server.ehlo()  # Re-identify ourselves over TLS connection
                
                # Now try to login
                server.login(self.default_smtp_server, self.default_smtp_port)
                server.send_message(msg)
                
        except Exception as e:
            print(f"Email error: {str(e)}")  # Add better error logging
            # Don't raise the exception for notifications - just log it
            return False
        
        return True

    def send_email(self, recipient_email: str, subject: str, body: str, 
                   is_html: bool = True, sender_email: str = None, 
                   attachments: List[Tuple[str, BytesIO]] = None) -> bool:
        """Send an email with optional attachments"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = sender_email if sender_email else self.default_smtp_server
            msg['To'] = recipient_email
            
            # Add body
            msg.attach(MIMEText(body, 'html' if is_html else 'plain'))
            
            # Add attachments if any
            if attachments:
                for filename, content in attachments:
                    attachment = MIMEApplication(content.getvalue(), _subtype='pdf')
                    attachment.add_header('Content-Disposition', 'attachment', 
                                       filename=filename)
                    msg.attach(attachment)
            
            # If not configured to send real emails, just log it
            if not self.send_real_emails:
                print(f"Email sending disabled.")
                print(f"Would send email to {recipient_email}")
                print(f"Subject: {subject}")
                print(f"Body: {body}")
                return True
            
            # Use organization SMTP settings if configured, otherwise use defaults
            smtp_server = self.org_smtp_server or self.default_smtp_server
            smtp_port = self.org_smtp_port or self.default_smtp_port
            smtp_password = self.org_smtp_password
            
            if not smtp_server or not smtp_port:
                print("SMTP settings not configured")
                return False
            
            # Connect to SMTP server and send
            with self._get_smtp_connection(smtp_server, smtp_port) as server:
                print(f"Connected to SMTP server {smtp_server}:{smtp_port}")
                
                if self.smtp_use_tls and not self.smtp_use_ssl:
                    server.starttls()
                    print("TLS encryption enabled")
                
                print(f"Attempting login for {sender_email}")
                server.login(sender_email, smtp_password)
                print("Login successful")
                
                server.send_message(msg)
                
            print(f"Email sent successfully to {recipient_email}")
            return True
            
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
            import traceback
            traceback.print_exc()
            return False 