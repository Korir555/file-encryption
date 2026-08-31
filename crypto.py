"""
Hybrid encryption module: AES-256 for data + RSA for key exchange
"""
import os
import json
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from datetime import datetime

class HybridEncryption:
    """AES-256-GCM + RSA hybrid encryption with HMAC integrity"""
    
    SALT_SIZE = 16  # 128 bits
    NONCE_SIZE = 12  # 96 bits for GCM
    TAG_SIZE = 16  # 128 bits (16 bytes)
    KEY_SIZE = 32  # 256 bits (32 bytes)
    PBKDF2_ITERATIONS = 100000  # NIST recommendation
    
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """Generate RSA keypair for key exchange"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
        """Derive AES key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(HybridEncryption.SALT_SIZE)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=HybridEncryption.KEY_SIZE,
            salt=salt,
            iterations=HybridEncryption.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    @staticmethod
    def encrypt_file_with_password(file_path: str, password: str) -> dict:
        """
        Encrypt file with AES-256-GCM using password-derived key
        Returns: {encrypted_data, salt, nonce, tag, plaintext_hash}
        """
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Derive key from password
        key, salt = HybridEncryption.derive_key_from_password(password)
        
        # Generate random nonce for GCM
        nonce = os.urandom(HybridEncryption.NONCE_SIZE)
        
        # Encrypt with AES-256-GCM (authenticated encryption)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag  # Authentication tag
        
        # Compute HMAC of plaintext for integrity (defense in depth)
        plaintext_hmac = hmac.new(
            key,
            plaintext,
            hashlib.sha256
        ).digest()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'salt': base64.b64encode(salt).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'hmac': base64.b64encode(plaintext_hmac).decode(),
            'filename': os.path.basename(file_path),
            'timestamp': datetime.utcnow().isoformat(),
            'algorithm': 'AES-256-GCM'
        }
    
    @staticmethod
    def decrypt_file_with_password(encrypted_data: dict, password: str) -> bytes:
        """
        Decrypt file encrypted with AES-256-GCM
        Verifies HMAC tag and GCM authentication tag
        """
        try:
            # Decode base64 components
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            salt = base64.b64decode(encrypted_data['salt'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            tag = base64.b64decode(encrypted_data['tag'])
            stored_hmac = base64.b64decode(encrypted_data['hmac'])
            
            # Derive same key from password
            key, _ = HybridEncryption.derive_key_from_password(password, salt)
            
            # Decrypt with AES-256-GCM
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Verify HMAC for additional integrity check
            computed_hmac = hmac.new(
                key,
                plaintext,
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(computed_hmac, stored_hmac):
                raise ValueError('HMAC verification failed - file may be corrupted')
            
            return plaintext
        
        except Exception as e:
            raise ValueError(f'Decryption failed: {str(e)}')
    
    @staticmethod
    def encrypt_file_with_rsa(file_path: str, public_key):
        """
        Encrypt file with AES-256-GCM, then encrypt AES key with RSA
        Hybrid approach: RSA for key exchange, AES for bulk data encryption
        """
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Generate random AES key
        aes_key = os.urandom(HybridEncryption.KEY_SIZE)
        nonce = os.urandom(HybridEncryption.NONCE_SIZE)
        
        # Encrypt file with AES-256-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        # Encrypt AES key with RSA public key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # HMAC for integrity
        file_hmac = hmac.new(
            aes_key,
            plaintext,
            hashlib.sha256
        ).digest()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'hmac': base64.b64encode(file_hmac).decode(),
            'filename': os.path.basename(file_path),
            'timestamp': datetime.utcnow().isoformat(),
            'algorithm': 'AES-256-GCM + RSA-2048'
        }
    
    @staticmethod
    def decrypt_file_with_rsa(encrypted_data: dict, private_key) -> bytes:
        """Decrypt file encrypted with hybrid AES-256 + RSA approach"""
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_key'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            tag = base64.b64decode(encrypted_data['tag'])
            stored_hmac = base64.b64decode(encrypted_data['hmac'])
            
            # Decrypt AES key with RSA private key
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file with AES key
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Verify HMAC
            computed_hmac = hmac.new(
                aes_key,
                plaintext,
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(computed_hmac, stored_hmac):
                raise ValueError('HMAC verification failed')
            
            return plaintext
        
        except Exception as e:
            raise ValueError(f'Decryption failed: {str(e)}')
    
    @staticmethod
    def serialize_public_key(public_key) -> str:
        """Serialize RSA public key to PEM format"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    @staticmethod
    def serialize_private_key(private_key, password: str = None) -> str:
        """Serialize RSA private key to PEM format (encrypted with password)"""
        if password:
            encryption_algo = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algo = serialization.NoEncryption()
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        return pem.decode('utf-8')
    
    @staticmethod
    def deserialize_public_key(pem: str):
        """Load RSA public key from PEM format"""
        return serialization.load_pem_public_key(
            pem.encode('utf-8'),
            backend=default_backend()
        )
    
    @staticmethod
    def deserialize_private_key(pem: str, password: str = None):
        """Load RSA private key from PEM format"""
        password_bytes = password.encode('utf-8') if password else None
        return serialization.load_pem_private_key(
            pem.encode('utf-8'),
            password=password_bytes,
            backend=default_backend()
        )
