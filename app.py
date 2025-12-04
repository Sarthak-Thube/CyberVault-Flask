from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
from PIL import Image

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'  # Change this for security
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # pyright: ignore[reportAttributeAccessIssue]

# --- SECURITY UTILS ---
# We generate a key based on the app secret (Simplified for beginner project)
# In production, every user should have their own derived key.
key = Fernet.generate_key()
cipher_suite = Fernet(key)


def encrypt(text):
    return cipher_suite.encrypt(text.encode()).decode()


def decrypt(text):
    try:
        return cipher_suite.decrypt(text.encode()).decode()
    except:
        return "[Error: Decryption Failed]"

def validate_password_strength(pwd: str) -> bool:
    # simple validator: length >= 8 and has upper, lower, digit, special
    if len(pwd) < 8:
        return False
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)
    return has_upper and has_lower and has_digit and has_special


def password_suggestion_text() -> str:
    return (
        "Use 12+ characters, mix upper, lower, numbers and symbols, "
        "avoid reuse and personal information."
    )



# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    passwords = db.relationship('Password', backref='owner', lazy=True)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(150))
    site_user = db.Column(db.String(150))
    site_pass = db.Column(db.String(500))  # Stored Encrypted
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# --- STEGANOGRAPHY LOGIC ---
def hide_text(img_path, text, output_path):
    img = Image.open(img_path)
    text += "#####"  # Delimiter
    binary_text = ''.join(format(ord(i), '08b') for i in text)
    data = tuple(img.getdata())
    new_data = []
    idx = 0
    for pixel in data:
        r, g, b = pixel[0], pixel[1], pixel[2]
        if idx < len(binary_text):
            r = (r & ~1) | int(binary_text[idx])
            idx += 1
        new_data.append((r, g, b))
    img.putdata(new_data)
    img.save(output_path, "PNG")


def reveal_text(img_path):
    img = Image.open(img_path)
    data = list(img.getdata())
    binary_text = ""
    for pixel in data:
        binary_text += str(pixel[0] & 1)

    # Convert binary to string
    all_text = ""
    for i in range(0, len(binary_text), 8):
        byte = binary_text[i:i + 8]
        all_text += chr(int(byte, 2))
        if all_text.endswith("#####"):
            return all_text[:-5]
    return "No hidden message found"


# --- ROUTES ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        if not validate_password_strength(password):
            flash('Password is too weak. Use at least 8 characters with upper, lower, digit and symbol.')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('login.html', register_mode=True)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        site = request.form.get('site')
        u_name = request.form.get('u_name')
        p_word = request.form.get('p_word')

        if not validate_password_strength(p_word):
            flash('Vault password is weak. Consider using the generator for a strong password.')
            return redirect(url_for('dashboard'))

        enc_pass = encrypt(p_word)
        new_pass = Password(site=site, site_user=u_name, site_pass=enc_pass, owner=current_user)
        db.session.add(new_pass)
        db.session.commit()
        return redirect(url_for('dashboard'))

    user_passwords = Password.query.filter_by(user_id=current_user.id).all()
    # Decrypt for display
    display_data = []
    for p in user_passwords:
        display_data.append({
            'site': p.site,
            'user': p.site_user,
            'pass': decrypt(p.site_pass)
        })
    return render_template('dashboard.html', passwords=display_data, suggestion=password_suggestion_text())


@app.route('/stego', methods=['GET', 'POST'])
@login_required
def stego():
    result_text = None
    if request.method == 'POST':
        action = request.form.get('action')
        file = request.files['image']

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            if action == 'hide':
                site = request.form.get('site')
                u_name = request.form.get('u_name')
                p_word = request.form.get('p_word')
                notes = request.form.get('notes', '')

                text = f"SITE:{site}\nUSER:{u_name}\nPASS:{p_word}\nNOTES:{notes}"
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'stego_' + filename)
                hide_text(filepath, text, output_path)
                return send_file(output_path, as_attachment=True)

            elif action == 'reveal':
                result_text = reveal_text(filepath)

    return render_template('stego.html', result=result_text)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    with app.app_context():
        db.create_all()
    app.run(debug=True)