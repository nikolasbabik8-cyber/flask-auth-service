from flask_cors import CORS
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import random
import string
from functools import wraps

app = Flask(__name__)CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///eclipse.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ADMIN_PASSWORD'] = os.environ.get('ADMIN_PASSWORD', 'changeme')

db = SQLAlchemy(app)

class Key(db.Model):
    __tablename__ = 'keys'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    hwid = db.Column(db.String(256), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

def generate_key():
    chars = string.ascii_uppercase + string.digits
    parts = ['ECLPS'] + [''.join(random.choices(chars, k=4)) for _ in range(4)]
    return '-'.join(parts)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        password = request.headers.get('X-Admin-Password')
        if password != app.config['ADMIN_PASSWORD']:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()
    if not data or 'key' not in data or 'hwid' not in data:
        return jsonify({'valid': False, 'reason': 'Missing key or hwid'}), 400

    k = Key.query.filter_by(key=data['key']).first()

    if not k:
        return jsonify({'valid': False, 'reason': 'Invalid key'}), 200
    if not k.is_active:
        return jsonify({'valid': False, 'reason': 'Key is banned'}), 200
    if k.expires_at and datetime.utcnow() > k.expires_at:
        return jsonify({'valid': False, 'reason': 'Key expired'}), 200
    if k.hwid is None:
        k.hwid = data['hwid']
    elif k.hwid != data['hwid']:
        return jsonify({'valid': False, 'reason': 'HWID mismatch'}), 200

    k.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({'valid': True, 'reason': 'OK'}), 200

@app.route('/generate', methods=['POST'])
@admin_required
def generate():
    data = request.get_json() or {}
    days = data.get('days', 30)
    key = generate_key()
    expires = datetime.utcnow() + timedelta(days=days) if days else None
    new_key = Key(key=key, expires_at=expires)
    db.session.add(new_key)
    db.session.commit()
    return jsonify({'key': key, 'expires_at': str(expires)}), 201

@app.route('/ban', methods=['POST'])
@admin_required
def ban():
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'error': 'Missing key'}), 400
    k = Key.query.filter_by(key=data['key']).first()
    if not k:
        return jsonify({'error': 'Key not found'}), 404
    k.is_active = False
    db.session.commit()
    return jsonify({'success': True, 'key': data['key']}), 200

@app.route('/unban', methods=['POST'])
@admin_required
def unban():
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'error': 'Missing key'}), 400
    k = Key.query.filter_by(key=data['key']).first()
    if not k:
        return jsonify({'error': 'Key not found'}), 404
    k.is_active = True
    db.session.commit()
    return jsonify({'success': True, 'key': data['key']}), 200

@app.route('/reset-hwid', methods=['POST'])
@admin_required
def reset_hwid():
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'error': 'Missing key'}), 400
    k = Key.query.filter_by(key=data['key']).first()
    if not k:
        return jsonify({'error': 'Key not found'}), 404
    k.hwid = None
    db.session.commit()
    return jsonify({'success': True, 'message': 'HWID reset'}), 200

@app.route('/keys', methods=['GET'])
@admin_required
def list_keys():
    keys = Key.query.order_by(Key.created_at.desc()).all()
    return jsonify([{
        'key': k.key,
        'hwid': k.hwid,
        'is_active': k.is_active,
        'expires_at': str(k.expires_at) if k.expires_at else 'Never',
        'created_at': str(k.created_at),
        'last_seen': str(k.last_seen) if k.last_seen else 'Never'
    } for k in keys]), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(debug=False)
