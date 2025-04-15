from fpdf import FPDF
from datetime import datetime
import qrcode
from io import BytesIO
from PyPDF2 import PdfReader, PdfWriter, PdfMerger
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
import time
import os
import tempfile

class AgreementPDF:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = self.styles['Heading1']
        self.normal_style = self.styles['Normal']
        self.signature_style = self.styles['Normal']

    def generate_agreement_pdf(self, agreement_id: str, title: str, content: str, recipient_email: str, signing_url: str) -> BytesIO:
        """Generate a PDF with agreement content and signing link/QR code"""
        output = BytesIO()
        pdf = FPDF()
        pdf.add_page()
        
        # Add header
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, title, ln=True, align='C')
        
        # Add agreement ID and date
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 10, f'Agreement ID: {agreement_id}', ln=True)
        pdf.cell(0, 10, f'Date: {datetime.now().strftime("%Y-%m-%d")}', ln=True)
        
        # Add content
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 10, content)
        
        # Add signing instructions
        pdf.ln(20)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'To sign this document:', ln=True)
        pdf.set_font('Arial', '', 12)
        
        # Add signing link
        pdf.cell(0, 10, '1. Visit the secure signing page:', ln=True)
        pdf.set_text_color(0, 0, 255)
        pdf.cell(0, 10, signing_url, ln=True)
        pdf.set_text_color(0, 0, 0)
        
        # Generate QR code in memory
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(signing_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Create a temporary file for the QR image
        tmp_dir = tempfile.gettempdir()
        tmp_qr_path = os.path.join(tmp_dir, f"qr_{agreement_id}.png")
        tmp_pdf_path = os.path.join(tmp_dir, f"pdf_{agreement_id}.pdf")
        
        try:
            # Save QR code to temp file
            qr_img.save(tmp_qr_path)
            
            # Add QR code to PDF
            pdf.image(tmp_qr_path, x=75, y=pdf.get_y(), w=60)
            
            # Write PDF to temporary file first
            pdf.output(tmp_pdf_path)
            
            # Read the temporary file into BytesIO
            with open(tmp_pdf_path, 'rb') as f:
                output.write(f.read())
            
            output.seek(0)
            return output
            
        finally:
            # Clean up temp files
            for temp_file in [tmp_qr_path, tmp_pdf_path]:
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except:
                        pass

    def generate_signed_pdf(self, agreement_id: str, title: str, content: str, recipient_email: str, signature_text: str) -> BytesIO:
        """Generate a new signed PDF in memory"""
        output = BytesIO()
        
        # Create PDF in memory
        doc = SimpleDocTemplate(output, pagesize=letter)
        story = []
        
        # Add title
        story.append(Paragraph(title, self.title_style))
        story.append(Spacer(1, 12))
        
        # Add content
        story.append(Paragraph(content, self.normal_style))
        story.append(PageBreak())
        
        # Add signature page - process each line separately
        lines = signature_text.split('\n')
        for line in lines:
            if line.strip():  # Skip empty lines
                story.append(Paragraph(line.strip(), self.signature_style))
            else:
                # Add a small spacer for empty lines
                story.append(Spacer(1, 6))
        
        # Build PDF
        doc.build(story)
        output.seek(0)
        return output

    def _create_signature_page(self, signature_text: str) -> BytesIO:
        """Create a signature page as a separate PDF in memory"""
        output = BytesIO()
        
        # Create PDF in memory
        doc = SimpleDocTemplate(output, pagesize=letter)
        story = []
        
        # Process signature text to ensure proper line breaks
        lines = signature_text.split('\n')
        for line in lines:
            if line.strip():  # Skip empty lines
                story.append(Paragraph(line.strip(), self.signature_style))
            else:
                # Add a small spacer for empty lines
                story.append(Spacer(1, 6))
        
        # Build PDF
        doc.build(story)
        output.seek(0)
        return output

    def append_signature_page(self, original_pdf_bytes: BytesIO, agreement_id: str, signature_text: str) -> BytesIO:
        """Append signature page to existing PDF in memory"""
        output = BytesIO()
        
        # Create PDF merger
        merger = PdfMerger()
        
        # Add original PDF
        merger.append(PdfReader(original_pdf_bytes))
        
        # Create and add signature page
        signature_pdf = self._create_signature_page(signature_text)
        merger.append(PdfReader(signature_pdf))
        
        # Write the merged PDF to memory
        merger.write(output)
        output.seek(0)
        return output 