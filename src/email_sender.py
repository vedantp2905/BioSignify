import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import os
from dotenv import load_dotenv

class EmailSender:
    def __init__(self):
        """Initialize email sender with SMTP settings from environment"""
        load_dotenv()
        
        self.smtp_server = os.getenv('SMTP_SERVER')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.sender_email = os.getenv('SENDER_EMAIL')
        self.sender_password = os.getenv('SENDER_PASSWORD')
        
        # Validate settings
        if not all([self.smtp_server, self.smtp_port, self.sender_email, self.sender_password]):
            raise ValueError("Missing email configuration in .env file")
        
    def send_agreement_email(self, recipient_email: str, agreement_id: str, pdf_path: str, signing_url: str):
        """Send initial agreement email with PDF attachment and signing link"""
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = f"New Agreement for Review: {agreement_id}"
            
            body = f"""
            A new agreement has been created for your review and signature.
            
            Agreement ID: {agreement_id}
            
            To sign this agreement, please click the following link:
            {signing_url}
            
            The agreement document is attached for your review.
            """
            msg.attach(MIMEText(body, 'plain'))
            
            if not os.path.exists(pdf_path):
                raise FileNotFoundError(f"PDF file not found at: {pdf_path}")
            
            # Attach PDF
            with open(pdf_path, 'rb') as f:
                pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                pdf_attachment.add_header(
                    'Content-Disposition', 'attachment', 
                    filename=os.path.basename(pdf_path)
                )
                msg.attach(pdf_attachment)
            
            # Send email
            print(f"Connecting to SMTP server: {self.smtp_server}:{self.smtp_port}")
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            
        except Exception as e:
            raise Exception(f"Failed to send email: {str(e)}")

    def send_signed_agreement_email(self, recipient_email: str, agreement_id: str, pdf_path: str, signature: str):
        """Send signed agreement email with PDF attachment"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = f"Signed Agreement: {agreement_id}"
            
            body = f"""
            Your agreement has been successfully signed.
            
            Agreement ID: {agreement_id}
            Digital Signature: {signature}
            
            The signed document is attached for your records.
            """
            msg.attach(MIMEText(body, 'plain'))
            
            if not os.path.exists(pdf_path):
                raise FileNotFoundError(f"PDF file not found at: {pdf_path}")
            
            # Attach PDF
            with open(pdf_path, 'rb') as f:
                pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                pdf_attachment.add_header(
                    'Content-Disposition', 'attachment', 
                    filename=os.path.basename(pdf_path)
                )
                msg.attach(pdf_attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
        except Exception as e:
            raise Exception(f"Failed to send email: {str(e)}") 