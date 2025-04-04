from fpdf import FPDF
from datetime import datetime
import qrcode
from io import BytesIO
import tempfile
import os
from PyPDF2 import PdfReader, PdfWriter

class AgreementPDF:
    def generate_agreement_pdf(self, agreement_id: str, title: str, content: str, recipient_email: str, signing_url: str) -> str:
        """Generate a PDF with agreement content and signing link/QR code"""
        self.pdf = FPDF()
        self.pdf.add_page()
        
        # Add header
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, title, ln=True, align='C')
        
        # Add agreement ID and date
        self.pdf.set_font('Arial', '', 10)
        self.pdf.cell(0, 10, f'Agreement ID: {agreement_id}', ln=True)
        self.pdf.cell(0, 10, f'Date: {datetime.now().strftime("%Y-%m-%d")}', ln=True)
        
        # Add content
        self.pdf.set_font('Arial', '', 12)
        self.pdf.multi_cell(0, 10, content)
        
        # Add signing instructions
        self.pdf.ln(20)
        self.pdf.set_font('Arial', 'B', 14)
        self.pdf.cell(0, 10, 'To sign this document:', ln=True)
        self.pdf.set_font('Arial', '', 12)
        
        # Add signing link
        self.pdf.cell(0, 10, '1. Visit the secure signing page:', ln=True)
        self.pdf.set_text_color(0, 0, 255)
        self.pdf.cell(0, 10, signing_url, ln=True)
        self.pdf.set_text_color(0, 0, 0)
        
        # Generate and add QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(signing_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to bytes
        qr_bytes = BytesIO()
        qr_img.save(qr_bytes, format='PNG')
        
        # Save QR code bytes to a temporary file
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_qr:
            temp_qr.write(qr_bytes.getvalue())
            temp_qr.flush()
            
            # Add QR code to PDF
            self.pdf.image(temp_qr.name, x=75, y=self.pdf.get_y(), w=60)
        
        # Clean up temporary file
        os.unlink(temp_qr.name)
        
        # Add signature field
        self.pdf.add_page()
        self.pdf.cell(0, 10, 'Signature:', ln=True)
        self.pdf.set_font('Arial', '', 12)
        
        # Add clickable link instead of JavaScript
        self.pdf.set_text_color(0, 0, 255)
        self.pdf.cell(0, 10, 'Click here to open signing page', ln=True, link=signing_url)
        self.pdf.set_text_color(0, 0, 0)
        
        # Save PDF
        filename = f"agreement_{agreement_id}.pdf"
        self.pdf.output(filename)
        return filename

    def generate_signed_pdf(self, agreement_id: str, title: str, content: str, recipient_email: str, signature: str) -> str:
        """Generate a PDF with agreement content and signature"""
        self.pdf = FPDF()
        # Set UTF-8 encoding
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
        self.pdf.add_page()
        
        # Add header with "SIGNED" watermark
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.set_text_color(200, 200, 200)
        self.pdf.cell(0, 10, 'SIGNED', ln=True, align='C')
        self.pdf.set_text_color(0, 0, 0)
        
        # Add title
        self.pdf.cell(0, 10, title, ln=True, align='C')
        
        # Add agreement details
        self.pdf.set_font('Arial', '', 10)
        self.pdf.cell(0, 10, f'Agreement ID: {agreement_id}', ln=True)
        self.pdf.cell(0, 10, f'Date: {datetime.now().strftime("%Y-%m-%d")}', ln=True)
        self.pdf.cell(0, 10, f'Signed by: {recipient_email}', ln=True)
        
        # Add content
        self.pdf.set_font('Arial', '', 12)
        self.pdf.multi_cell(0, 10, content)
        
        # Add verification text with checkmark symbol
        self.pdf.ln(10)
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.set_text_color(0, 128, 0)  # Green color for verification
        # Use a simple ASCII checkmark instead of Unicode
        self.pdf.cell(0, 10, '[VERIFIED] Validated by facial biometrics', ln=True)
        self.pdf.set_text_color(0, 0, 0)  # Reset to black
        
        # Add signature section
        self.pdf.ln(10)
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(0, 10, 'Digital Signature:', ln=True)
        self.pdf.set_font('Courier', '', 10)
        self.pdf.multi_cell(0, 5, signature)
        
        # Save PDF
        filename = f"signed_agreement_{agreement_id}.pdf"
        self.pdf.output(filename)
        return filename

    def append_signature_page(self, original_pdf_path: str, agreement_id: str, signature: str) -> str:
        """Append a signature page to an existing PDF"""
        # Create signature page with FPDF
        signature_pdf = FPDF()
        signature_pdf.add_page()
        
        # Add verification header
        signature_pdf.set_font('Arial', 'B', 14)
        signature_pdf.cell(0, 10, 'Agreement Verification', ln=True, align='C')
        
        # Add timestamp
        signature_pdf.set_font('Arial', '', 10)
        signature_pdf.cell(0, 10, f'Signed on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
        
        # Add verification text
        signature_pdf.ln(10)
        signature_pdf.set_font('Arial', 'B', 12)
        signature_pdf.set_text_color(0, 128, 0)
        signature_pdf.cell(0, 10, '[VERIFIED] Validated by facial biometrics', ln=True)
        signature_pdf.set_text_color(0, 0, 0)
        
        # Add signature
        signature_pdf.ln(10)
        signature_pdf.set_font('Arial', 'B', 12)
        signature_pdf.cell(0, 10, 'Digital Signature:', ln=True)
        signature_pdf.set_font('Courier', '', 10)
        signature_pdf.multi_cell(0, 5, signature)
        
        # Save signature page temporarily
        temp_signature_path = f"temp_signature_{agreement_id}.pdf"
        signature_pdf.output(temp_signature_path)
        
        try:
            # Merge original PDF with signature page
            output_path = f"signed_agreement_{agreement_id}.pdf"
            
            # Read the original PDF
            original = PdfReader(original_pdf_path)
            signature_page = PdfReader(temp_signature_path)
            
            # Create output PDF
            output = PdfWriter()
            
            # Add all pages from original PDF
            for page in original.pages:
                output.add_page(page)
            
            # Add signature page
            output.add_page(signature_page.pages[0])
            
            # Save the merged PDF
            with open(output_path, "wb") as output_file:
                output.write(output_file)
                
            return output_path
            
        finally:
            # Clean up temporary signature page
            if os.path.exists(temp_signature_path):
                os.remove(temp_signature_path) 