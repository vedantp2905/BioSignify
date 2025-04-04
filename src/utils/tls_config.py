from OpenSSL import SSL
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

class TLSConfig:
    def __init__(self):
        self.cert_path = os.path.join(os.path.dirname(__file__), '..', '..', 'certs')
        os.makedirs(self.cert_path, exist_ok=True)
        
        # Generate or load certificates
        self.cert_file = os.path.join(self.cert_path, 'server.crt')
        self.key_file = os.path.join(self.cert_path, 'server.key')
        
        if not (os.path.exists(self.cert_file) and os.path.exists(self.key_file)):
            self._generate_self_signed_cert()
    
    def get_ssl_context(self):
        """Create SSL context with TLS 1.3"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.cert_file, self.key_file)
        
        # Use more widely supported cipher suites
        context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
        
        # Enable forward secrecy
        context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
        
        return context

    def _generate_self_signed_cert(self):
        """Generate self-signed certificate for development"""
        # Generate key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"BioSign Development"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Development"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Save private key
        with open(self.key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save certificate
        with open(self.cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM)) 