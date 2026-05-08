from flask import Flask, render_template, request, redirect, url_for, make_response, flash, g
from pymongo import MongoClient
from bson import ObjectId
import json, os, secrets, time, base64
from crypto import rsa_scratch as rsa
from crypto import ecc_scratch as ecc
from crypto.mac_hash import hash_password, verify_password, hmac_sha256, make_otp, verify_otp

# =========================
# MongoDB Configuration
# =========================
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME = os.environ.get('MONGO_DB_NAME', 'cse447_secure_event_club')

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
keys_col = db['keys']
users_col = db['users']
posts_col = db['posts']
sessions_col = db['sessions']

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

ROOT_RSA = None
DATA_RSA = None
DATA_ECC = None
SESSION_KEY = None


def mongo_safe(obj):
    """Convert cryptographic big integers into strings before MongoDB storage.
    MongoDB supports only signed 64-bit integers, while RSA/ECC numbers are much larger.
    """
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, tuple):
        return [mongo_safe(x) for x in obj]
    if isinstance(obj, list):
        return [mongo_safe(x) for x in obj]
    if isinstance(obj, dict):
        return {k: mongo_safe(v) for k, v in obj.items()}
    return obj


def crypto_ints(obj):
    """Convert string-stored cryptographic numbers back to integers for RSA/ECC math."""
    if isinstance(obj, str):
        if obj.isdigit():
            return int(obj)
        return obj
    if isinstance(obj, list):
        return [crypto_ints(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(crypto_ints(x) for x in obj)
    if isinstance(obj, dict):
        return {k: crypto_ints(v) for k, v in obj.items()}
    return obj


def init_db():
    """Create indexes for MongoDB collections."""
    keys_col.create_index('name', unique=True)
    users_col.create_index('created_at')
    posts_col.create_index('updated_at')
    sessions_col.create_index('expires_at', expireAfterSeconds=0)


def bootstrap_keys():
    """Generate/load RSA + ECC keys. All keys are stored in MongoDB."""
    global ROOT_RSA, DATA_RSA, DATA_ECC, SESSION_KEY

    root = keys_col.find_one({'name': 'root_rsa'})
    if not root:
        ROOT_RSA = rsa.generate_keypair(1024)
        keys_col.insert_one({
            'name': 'root_rsa',
            'algorithm': 'RSA',
            'public_json': mongo_safe(ROOT_RSA['public']),
            'private_wrapped': mongo_safe(ROOT_RSA['private']),
            'status': 'active',
            'created_at': int(time.time()),
            'rotated_at': None
        })

        data_rsa = rsa.generate_keypair(1024)
        data_ecc = ecc.generate_keypair()
        keys_col.insert_many([
            {
                'name': 'data_rsa',
                'algorithm': 'RSA',
                'public_json': mongo_safe(data_rsa['public']),
                'private_wrapped': rsa.encrypt_text(json.dumps(mongo_safe(data_rsa['private'])), ROOT_RSA['public']),
                'status': 'active',
                'created_at': int(time.time()),
                'rotated_at': None
            },
            {
                'name': 'data_ecc',
                'algorithm': 'ECC',
                'public_json': mongo_safe(data_ecc['public']),
                'private_wrapped': rsa.encrypt_text(json.dumps(mongo_safe(data_ecc['private'])), ROOT_RSA['public']),
                'status': 'active',
                'created_at': int(time.time()),
                'rotated_at': None
            }
        ])
    else:
        ROOT_RSA = {'public': crypto_ints(root['public_json']), 'private': crypto_ints(root['private_wrapped'])}

    r = keys_col.find_one({'algorithm': 'RSA', 'name': {'$regex': '^data_rsa'}, 'status': 'active'}, sort=[('created_at', -1)])
    e = keys_col.find_one({'algorithm': 'ECC', 'name': {'$regex': '^data_ecc'}, 'status': 'active'}, sort=[('created_at', -1)])
    DATA_RSA = {'public': crypto_ints(r['public_json']), 'private': crypto_ints(json.loads(rsa.decrypt_text(r['private_wrapped'], ROOT_RSA['private'])))}
    DATA_ECC = {'public': crypto_ints(e['public_json']), 'private': crypto_ints(json.loads(rsa.decrypt_text(e['private_wrapped'], ROOT_RSA['private'])))}
    SESSION_KEY = (json.dumps(ROOT_RSA['private'])[:64]).encode()


def mac_for(*parts):
    return hmac_sha256(SESSION_KEY, ('|'.join(str(p) for p in parts)).encode())


def enc_rsa(s): return rsa.encrypt_text(s or '', DATA_RSA['public'])
def dec_rsa(s): return rsa.decrypt_text(s, DATA_RSA['private'])
def enc_ecc(s): return ecc.encrypt_text(s or '', DATA_ECC['public'])
def dec_ecc(s): return ecc.decrypt_text(s, DATA_ECC['private'])


def create_session(user_id, role):
    payload = json.dumps({'uid': str(user_id), 'role': role, 'exp': int(time.time()) + 3600})
    sig = mac_for(payload)
    token = base64.urlsafe_b64encode(payload.encode()).decode() + '.' + sig
    sessions_col.insert_one({
        'user_id': str(user_id),
        'token_mac': sig,
        'ip_address': request.remote_addr,
        'created_at': int(time.time()),
        'expires_at': int(time.time()) + 3600
    })
    return token


def read_session():
    tok = request.cookies.get('session_token')
    if not tok or '.' not in tok:
        return None
    b64, sig = tok.rsplit('.', 1)
    try:
        payload = base64.urlsafe_b64decode(b64.encode()).decode()
    except Exception:
        return None
    if mac_for(payload) != sig:
        return None
    data = json.loads(payload)
    if data['exp'] < time.time():
        return None
    if not sessions_col.find_one({'user_id': data['uid'], 'token_mac': sig}):
        return None
    return data


@app.before_request
def load_user():
    g.session = read_session()


def login_required(fn):
    def wrapper(*args, **kwargs):
        if not g.session:
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def admin_required(fn):
    def wrapper(*args, **kwargs):
        if not g.session:
            return redirect(url_for('login'))
        if g.session['role'] != 'admin':
            return ('Access denied: admin role required', 403)
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        contact = request.form['contact']
        password = request.form['password']
        role = 'admin' if username.lower() == 'admin' else 'user'
        secret = secrets.token_hex(10)
        salt, digest = hash_password(password)

        username_enc = enc_rsa(username)
        email_enc = enc_rsa(email)
        contact_enc = enc_rsa(contact)
        profile_enc = enc_rsa('New member')
        twofa_enc = enc_ecc(secret)
        data_mac = mac_for(username_enc, email_enc, contact_enc, profile_enc, twofa_enc, role)

        users_col.insert_one({
            'username_enc': username_enc,
            'email_enc': email_enc,
            'contact_enc': contact_enc,
            'profile_enc': profile_enc,
            'role': role,
            'password_salt': salt,
            'password_hash': digest,
            'twofa_enc': twofa_enc,
            'data_mac': data_mac,
            'created_at': int(time.time())
        })
        return render_template('show_secret.html', secret=secret, code=make_otp(secret))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for u in users_col.find({}):
            if dec_rsa(u['username_enc']) == username and verify_password(password, u['password_salt'], u['password_hash']):
                resp = make_response(redirect(url_for('verify2fa')))
                resp.set_cookie('pending_uid', str(u['_id']), httponly=True, samesite='Strict', max_age=300)
                return resp
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify2fa():
    uid = request.cookies.get('pending_uid')
    if not uid:
        return redirect(url_for('login'))
    try:
        u = users_col.find_one({'_id': ObjectId(uid)})
    except Exception:
        return redirect(url_for('login'))
    if not u:
        return redirect(url_for('login'))
    secret = dec_ecc(u['twofa_enc'])
    if request.method == 'POST':
        if verify_otp(secret, request.form['code']):
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('session_token', create_session(u['_id'], u['role']), httponly=True, secure=False, samesite='Strict', max_age=3600)
            resp.delete_cookie('pending_uid')
            return resp
        flash('Invalid second factor code')
    return render_template('verify.html', demo_code=make_otp(secret))


@app.route('/dashboard')
@login_required
def dashboard():
    view = []
    for p in posts_col.find({}).sort('updated_at', -1):
        ok = p['mac'] == mac_for(p['user_id'], p['title_enc'], p['body_enc'], p['created_at'], p['updated_at'])
        view.append({
            'id': str(p['_id']),
            'user_id': p['user_id'],
            'title': dec_ecc(p['title_enc']),
            'body': dec_ecc(p['body_enc']),
            'ok': ok
        })
    return render_template('dashboard.html', posts=view, user=g.session)


@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def post_new():
    if request.method == 'POST':
        title_enc = enc_ecc(request.form['title'])
        body_enc = enc_ecc(request.form['body'])
        now = int(time.time())
        m = mac_for(g.session['uid'], title_enc, body_enc, now, now)
        posts_col.insert_one({
            'user_id': g.session['uid'],
            'title_enc': title_enc,
            'body_enc': body_enc,
            'mac': m,
            'created_at': now,
            'updated_at': now
        })
        return redirect(url_for('dashboard'))
    return render_template('post_form.html', post=None)


@app.route('/post/<pid>/edit', methods=['GET', 'POST'])
@login_required
def post_edit(pid):
    try:
        p = posts_col.find_one({'_id': ObjectId(pid)})
    except Exception:
        return ('Not found', 404)
    if not p:
        return ('Not found', 404)
    if g.session['role'] != 'admin' and p['user_id'] != g.session['uid']:
        return ('Access denied', 403)
    if request.method == 'POST':
        title_enc = enc_ecc(request.form['title'])
        body_enc = enc_ecc(request.form['body'])
        now = int(time.time())
        m = mac_for(p['user_id'], title_enc, body_enc, p['created_at'], now)
        posts_col.update_one({'_id': p['_id']}, {'$set': {
            'title_enc': title_enc,
            'body_enc': body_enc,
            'mac': m,
            'updated_at': now
        }})
        return redirect(url_for('dashboard'))
    post = {'id': str(p['_id']), 'title': dec_ecc(p['title_enc']), 'body': dec_ecc(p['body_enc'])}
    return render_template('post_form.html', post=post)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    u = users_col.find_one({'_id': ObjectId(g.session['uid'])})
    if request.method == 'POST':
        email_enc = enc_rsa(request.form['email'])
        contact_enc = enc_rsa(request.form['contact'])
        profile_enc = enc_rsa(request.form['profile'])
        data_mac = mac_for(u['username_enc'], email_enc, contact_enc, profile_enc, u['twofa_enc'], u['role'])
        users_col.update_one({'_id': u['_id']}, {'$set': {
            'email_enc': email_enc,
            'contact_enc': contact_enc,
            'profile_enc': profile_enc,
            'data_mac': data_mac
        }})
        u = users_col.find_one({'_id': ObjectId(g.session['uid'])})
    data = {
        'username': dec_rsa(u['username_enc']),
        'email': dec_rsa(u['email_enc']),
        'contact': dec_rsa(u['contact_enc']),
        'profile': dec_rsa(u['profile_enc']),
        'role': u['role'],
        'mac_ok': u['data_mac'] == mac_for(u['username_enc'], u['email_enc'], u['contact_enc'], u['profile_enc'], u['twofa_enc'], u['role'])
    }
    return render_template('profile.html', data=data)


@app.route('/admin')
@admin_required
def admin():
    user_view = []
    for u in users_col.find({}):
        user_view.append({
            'id': str(u['_id']),
            'username': dec_rsa(u['username_enc']),
            'email': dec_rsa(u['email_enc']),
            'role': u['role']
        })
    keys = []
    for k in keys_col.find({}).sort('created_at', 1):
        keys.append({
            'id': str(k['_id']),
            'name': k['name'],
            'algorithm': k['algorithm'],
            'status': k['status'],
            'created_at': k['created_at'],
            'rotated_at': k.get('rotated_at')
        })
    return render_template('admin.html', users=user_view, keys=keys)


@app.route('/admin/rotate', methods=['POST'])
@admin_required
def rotate():
    global DATA_RSA, DATA_ECC
    new_rsa = rsa.generate_keypair(1024)
    new_ecc = ecc.generate_keypair()
    now = int(time.time())

    keys_col.update_many({'name': {'$regex': '^data_'}, 'status': 'active'}, {'$set': {'status': 'rotated', 'rotated_at': now}})
    keys_col.insert_many([
        {
            'name': f'data_rsa_{now}',
            'algorithm': 'RSA',
            'public_json': mongo_safe(new_rsa['public']),
            'private_wrapped': rsa.encrypt_text(json.dumps(mongo_safe(new_rsa['private'])), ROOT_RSA['public']),
            'status': 'active',
            'created_at': now,
            'rotated_at': None
        },
        {
            'name': f'data_ecc_{now}',
            'algorithm': 'ECC',
            'public_json': mongo_safe(new_ecc['public']),
            'private_wrapped': rsa.encrypt_text(json.dumps(mongo_safe(new_ecc['private'])), ROOT_RSA['public']),
            'status': 'active',
            'created_at': now,
            'rotated_at': None
        }
    ])
    DATA_RSA = new_rsa
    DATA_ECC = new_ecc
    flash('New MongoDB RSA and ECC key records created. Old active data keys marked rotated.')
    return redirect(url_for('admin'))


@app.route('/logout')
def logout():
    tok = request.cookies.get('session_token')
    if tok and '.' in tok:
        _, sig = tok.rsplit('.', 1)
        sessions_col.delete_many({'token_mac': sig})
    resp = make_response(redirect(url_for('home')))
    resp.delete_cookie('session_token')
    return resp


if __name__ == '__main__':
    init_db()
    bootstrap_keys()
    print(f'Using MongoDB database: {DB_NAME}')
    app.run(debug=True)
