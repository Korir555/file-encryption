from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import os
import io
from datetime import datetime
from crypto import HybridEncryption

app = Flask(__name__, template_folder='templates')
CORS(app)

# In-memory RSA key storage (in production, use secure key management)
stored_keys = {}

@app.route('/', methods=['GET'])
def index():
    """Serve the encryption UI"""
    from flask import render_template
    return render_template('index.html')

# ==================== PASSWORD-BASED ENCRYPTION ====================

@app.route('/api/encrypt/password', methods=['POST'])
def encrypt_with_password():
    """Encrypt file with password-derived AES-256 key"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            return jsonify({'error': 'Password required'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Save temp file
        temp_path = f'/tmp/{file.filename}'
        file.save(temp_path)
        
        try:
            # Encrypt
            result = HybridEncryption.encrypt_file_with_password(temp_path, password)
            return jsonify(result), 200
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt/password', methods=['POST'])
def decrypt_with_password():
    """Decrypt file with password"""
    try:
        data = request.json
        password = data.get('password')
        encrypted_data = data.get('encrypted_data')
        
        if not password or not encrypted_data:
            return jsonify({'error': 'Password and encrypted data required'}), 400
        
        # Decrypt
        plaintext = HybridEncryption.decrypt_file_with_password(encrypted_data, password)
        
        # Return as downloadable file
        filename = encrypted_data.get('filename', 'decrypted_file')
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=filename
        ), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

# ==================== RSA KEY MANAGEMENT ====================

@app.route('/api/keys/generate', methods=['POST'])
def generate_rsa_keys():
    """Generate RSA keypair"""
    try:
        key_size = request.json.get('key_size', 2048)
        key_id = f"key_{datetime.utcnow().timestamp()}"
        
        private_key, public_key = HybridEncryption.generate_rsa_keypair(key_size)
        
        # Store keys (in production, use secure storage)
        stored_keys[key_id] = {
            'private': private_key,
            'public': public_key,
            'created': datetime.utcnow().isoformat(),
            'key_size': key_size
        }
        
        # Return public key in PEM format
        public_pem = HybridEncryption.serialize_public_key(public_key)
        
        return jsonify({
            'key_id': key_id,
            'public_key': public_pem,
            'key_size': key_size,
            'created': datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/<key_id>', methods=['GET'])
def get_public_key(key_id):
    """Retrieve stored public key"""
    if key_id not in stored_keys:
        return jsonify({'error': 'Key not found'}), 404
    
    key_data = stored_keys[key_id]
    public_pem = HybridEncryption.serialize_public_key(key_data['public'])
    
    return jsonify({
        'key_id': key_id,
        'public_key': public_pem,
        'key_size': key_data['key_size'],
        'created': key_data['created']
    }), 200

# ==================== HYBRID ENCRYPTION (RSA + AES) ====================

@app.route('/api/encrypt/hybrid', methods=['POST'])
def encrypt_with_hybrid():
    """Encrypt file with hybrid AES-256 + RSA"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        key_id = request.form.get('key_id')
        
        if not key_id or key_id not in stored_keys:
            return jsonify({'error': 'RSA key not found'}), 400
        
        # Save temp file
        temp_path = f'/tmp/{file.filename}'
        file.save(temp_path)
        
        try:
            # Encrypt with hybrid approach
            public_key = stored_keys[key_id]['public']
            result = HybridEncryption.encrypt_file_with_rsa(temp_path, public_key)
            result['key_id'] = key_id
            return jsonify(result), 200
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt/hybrid', methods=['POST'])
def decrypt_with_hybrid():
    """Decrypt file encrypted with hybrid approach"""
    try:
        data = request.json
        key_id = data.get('key_id')
        encrypted_data = data.get('encrypted_data')
        key_password = data.get('key_password')  # Password to unlock private key
        
        if not key_id or key_id not in stored_keys:
            return jsonify({'error': 'RSA key not found'}), 400
        
        if not encrypted_data:
            return jsonify({'error': 'Encrypted data required'}), 400
        
        # Get private key
        private_key = stored_keys[key_id]['private']
        
        # Decrypt
        plaintext = HybridEncryption.decrypt_file_with_rsa(encrypted_data, private_key)
        
        # Return as downloadable file
        filename = encrypted_data.get('filename', 'decrypted_file')
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=filename
        ), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

# ==================== UTILITY ENDPOINTS ====================

@app.route('/api/keys', methods=['GET'])
def list_keys():
    """List all stored key IDs and metadata"""
    keys_list = []
    for key_id, key_data in stored_keys.items():
        keys_list.append({
            'key_id': key_id,
            'key_size': key_data['key_size'],
            'created': key_data['created']
        })
    return jsonify({'keys': keys_list}), 200

@app.route('/api/keys/<key_id>', methods=['DELETE'])
def delete_key(key_id):
    """Delete stored RSA key"""
    if key_id in stored_keys:
        del stored_keys[key_id]
        return jsonify({'message': 'Key deleted'}), 200
    return jsonify({'error': 'Key not found'}), 404

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'file-encryption'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5001)
