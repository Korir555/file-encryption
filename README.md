# File Encryption Tool

Professional-grade file encryption and decryption application with hybrid cryptography (AES-256 + RSA), HMAC integrity verification, and secure key management. Built with Flask and React for accessibility and usability.

## Features

### Password-Based Encryption
- **AES-256-GCM** symmetric encryption derived from user passwords
- **PBKDF2** key derivation with 100,000 iterations and SHA-256
- **HMAC-SHA256** for file integrity verification (defense-in-depth)
- Fast encryption/decryption for any file size
- No external key management required

### RSA Hybrid Encryption
- **RSA-2048/3072/4096** for secure key exchange
- **AES-256-GCM** for bulk file encryption
- Combines asymmetric security with symmetric performance
- Ideal for multi-party file sharing and key distribution
- GCM authenticated encryption with built-in integrity

### Key Management
- Generate RSA keypairs on-demand (2048, 3072, 4096-bit options)
- Store public keys for file sharing
- Secure private key handling
- List and delete stored keys
- Export keys in standard PEM format

### Security Features
- **GCM Mode** — Authenticated encryption (no separate MAC needed, but we add HMAC too)
- **Random Nonces** — Cryptographically secure random generation
- **Constant-Time Comparison** — Prevents timing attacks on HMAC verification
- **PBKDF2** — Industry-standard password-based key derivation
- **Secure Random** — Uses `os.urandom()` from OS entropy pool

### User Interface
- Dark terminal aesthetic matching professional security environments
- Tabbed interface for encrypt/decrypt workflows
- Real-time status updates and error handling
- Copy-to-clipboard and file download functionality
- Responsive design for desktop and mobile
- No external dependencies required (pure browser/Flask)

## Technical Architecture

### Backend (Flask REST API)

**Core Endpoints:**
- `POST /api/encrypt/password` — Encrypt file with password
- `POST /api/decrypt/password` — Decrypt with password
- `POST /api/encrypt/hybrid` — Encrypt with RSA public key
- `POST /api/decrypt/hybrid` — Decrypt with RSA private key
- `POST /api/keys/generate` — Generate RSA keypair
- `GET /api/keys` — List stored keys
- `GET /api/keys/<key_id>` — Retrieve public key
- `DELETE /api/keys/<key_id>` — Delete key

**Cryptography Module (`crypto.py`):**
- `HybridEncryption.derive_key_from_password()` — PBKDF2 key derivation
- `HybridEncryption.encrypt_file_with_password()` — AES-256-GCM encryption
- `HybridEncryption.decrypt_file_with_password()` — Verification and decryption
- `HybridEncryption.encrypt_file_with_rsa()` — Hybrid encryption
- `HybridEncryption.decrypt_file_with_rsa()` — Hybrid decryption
- RSA key serialization/deserialization (PEM format)

### Frontend (React SPA)

**Features:**
- Dual-tab interface for encryption and decryption
- File upload with drag-and-drop support
- Password strength indicators (future)
- Key generation and management UI
- Results display with copy/download options
- Error handling and user feedback

## Installation

### Requirements
- Python 3.8+
- pip package manager
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Setup

```bash
# Clone repository
git clone https://github.com/Korir555/file-encryption.git
cd file-encryption

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Start the Application

```bash
python app.py
```

The application runs on `http://127.0.0.1:5001`

### Basic Workflow

#### Password-Based Encryption

1. **Encrypt:**
   - Select a file
   - Enter a strong password (8+ characters)
   - Click "ENCRYPT FILE"
   - Save the JSON output (contains all needed data for decryption)

2. **Decrypt:**
   - Paste the encrypted JSON
   - Enter the same password
   - Download decrypted file

#### RSA Key-Based Encryption

1. **Generate Keys:**
   - Select key size (2048/3072/4096 bits)
   - Click "GENERATE NEW KEYPAIR"
   - Copy and securely store the private key
   - Share the public key with others

2. **Encrypt for Others:**
   - Select file and paste recipient's public key
   - Encrypted file can only be decrypted by recipient with private key

3. **Decrypt Received Files:**
   - Paste encrypted JSON
   - Paste your private key
   - Download decrypted file

## Encryption Specifications

### AES-256-GCM
- **Algorithm:** Advanced Encryption Standard, 256-bit key
- **Mode:** Galois/Counter Mode (authenticated encryption)
- **Key Size:** 32 bytes (256 bits)
- **Nonce Size:** 12 bytes (96 bits)
- **Tag Size:** 16 bytes (128 bits)

### RSA
- **Key Sizes:** 2048, 3072, or 4096 bits
- **Public Exponent:** 65537 (standard)
- **Padding:** OAEP with SHA-256
- **MGF:** MGF1 with SHA-256

### Key Derivation (PBKDF2)
- **Algorithm:** PBKDF2-HMAC-SHA256
- **Iterations:** 100,000 (NIST recommendation)
- **Salt:** 16 bytes (128 bits) random
- **Output:** 32 bytes (256 bits)

### Integrity Verification
- **Method:** HMAC-SHA256
- **Scope:** Entire plaintext
- **Usage:** Verify file wasn't corrupted or tampered with

## Security Considerations

### Strengths
 Industry-standard algorithms (AES, RSA, PBKDF2, HMAC)
 Authenticated encryption (GCM mode prevents tampering)
 Defense-in-depth (HMAC + GCM tag)
 Secure random generation (OS entropy)
 Proper key derivation (100K PBKDF2 iterations)
 Constant-time comparison (timing attack prevention)

### Limitations
 In-memory key storage (production should use secure enclaves)
 No password strength validation (user responsibility)
 Browser-based UI means keys/passwords visible in memory
 Demo mode (keys stored in Flask process memory)

### Best Practices
1. Use strong passwords (20+ characters, mixed case, symbols)
2. Store private keys securely (encrypted at rest)
3. Never share private keys
4. Verify file integrity before trusting decrypted content
5. Use 4096-bit RSA for maximum security (slower but safer)
6. Keep Flask backend on trusted systems only

## API Usage

### Encrypt File (Password)

```bash
curl -X POST http://127.0.0.1:5001/api/encrypt/password \
  -F "file=@document.pdf" \
  -F "password=SecurePassword123"
```

**Response:**
```json
{
  "ciphertext": "base64_encoded_data...",
  "salt": "base64_encoded_salt...",
  "nonce": "base64_encoded_nonce...",
  "tag": "base64_encoded_tag...",
  "hmac": "base64_encoded_hmac...",
  "filename": "document.pdf",
  "timestamp": "2024-08-31T10:30:00",
  "algorithm": "AES-256-GCM"
}
```

### Decrypt File (Password)

```bash
curl -X POST http://127.0.0.1:5001/api/decrypt/password \
  -H "Content-Type: application/json" \
  -d '{
    "password": "SecurePassword123",
    "encrypted_data": { ... }
  }' \
  --output decrypted.pdf
```

### Generate RSA Keys

```bash
curl -X POST http://127.0.0.1:5001/api/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"key_size": 2048}'
```

**Response:**
```json
{
  "key_id": "key_1725194700.123",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "key_size": 2048,
  "created": "2024-08-31T10:30:00"
}
```

## Performance

- **AES-256 Encryption:** ~100-500 MB/s (CPU-dependent)
- **RSA Key Generation:** 2048-bit in ~0.5s, 4096-bit in ~2-3s
- **PBKDF2 Derivation:** ~100ms (intentionally slow for security)
- **File Upload:** Limited by network and browser (typically 100+ MB)

## Use Cases

- **Personal File Protection:** Encrypt sensitive documents at rest
- **Secure File Sharing:** Share encrypted files over insecure channels
- **Compliance:** Meet data protection requirements (GDPR, HIPAA)
- **Zero-Trust Networks:** Encrypt before uploading to untrusted storage
- **Backup Security:** Encrypt backups before cloud storage
- **Multi-Party Exchange:** RSA for secure key distribution before bulk file encryption

## Limitations & Future Work

**Current:**
- Password-based only (no interactive key management)
- Files processed in-memory (limits to available RAM)
- No scheduling or batch operations
- Demo-mode key storage (not production-ready)

**Future Enhancements:**
- Docker containerization for easy deployment
- Persistent encrypted key storage
- Streaming encryption for large files
- Batch encryption operations
- Client-side encryption (move crypto to browser)
- Key expiration and revocation
- Audit logging
- Integration with hardware security modules (HSM)
- Command-line interface (CLI) wrapper

## Troubleshooting

### "Failed to decrypt - Authentication tag mismatch"
- File data was corrupted
- Wrong password used
- Encrypted data was modified

### "RSA key size too large"
- Browser or server memory limit exceeded
- Try smaller key size (2048 instead of 4096)

### "PBKDF2 taking too long"
- Normal for security (intentionally slow)
- 100,000 iterations = ~100ms on modern CPU

### "File upload failed"
- Check file size (memory limits)
- Browser may have timeout on large files
- Try smaller files first

## Testing

```bash
# Encrypt test file
python -c "
from crypto import HybridEncryption
import os

# Create test file
with open('test.txt', 'w') as f:
    f.write('Hello, World!')

# Encrypt
result = HybridEncryption.encrypt_file_with_password('test.txt', 'password123')
print('Encrypted:', result)

# Decrypt
decrypted = HybridEncryption.decrypt_file_with_password(result, 'password123')
print('Decrypted:', decrypted.decode())
"
```

## Dependencies

- **cryptography** — Industry-standard cryptography library
- **Flask** — Web framework
- **Flask-CORS** — Cross-origin request handling

## License

MIT License — See LICENSE file for details

## Author

Emmanuel Kibet Korir (@Korir555)

Built as part of a professional cybersecurity portfolio demonstrating:
- Cryptography fundamentals (symmetric + asymmetric)
- Secure coding practices
- Full-stack application development
- Security tooling and deployment

## Contributing

Issues and pull requests welcome. For security issues, please report privately.

## References

- [NIST SP 800-132: PBKDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [NIST SP 800-38D: GCM Mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 3394: AES Key Wrap](https://tools.ietf.org/html/rfc3394)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
