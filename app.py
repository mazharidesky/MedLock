import os
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_mysqldb import MySQL
from functools import wraps
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
import json
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Konfigurasi MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'uts_pemrograman'
app.config['MYSQL_PORT'] = 3306

# Kunci enkripsi AES harus 16 byte untuk AES-128
AES_KEY = b'ThisIs16ByteKey!'  # Kunci harus tepat 16 byte

mysql = MySQL(app)

def encrypt_data(data):
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(json.dumps(data).encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

def generate_pdf(data):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 50, "Form Rekam Medis Anda Dekku")
    
    p.setFont("Helvetica", 12)
    y = height - 80
    for key, value in data.items():
        p.drawString(50, y, f"{key}: {value}")
        y -= 20

    p.showPage()
    p.save()
    buffer.seek(0)
    return buffer

def encrypt_data(data):
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(json.dumps(data).encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

def decrypt_data(encrypted_data):
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_bytes[:16]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes[16:]), AES.block_size)
    return decrypted_bytes.decode('utf-8')

def encrypt_password(password):
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

def decrypt_password(encrypted_password):
    encrypted_data = base64.b64decode(encrypted_password)
    iv = encrypted_data[:16]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted_bytes.decode('utf-8')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        _username = request.form['username']
        _password = request.form['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE name = %s", (_username,))
        user = cur.fetchone()
        cur.close()
        
        if user:
            stored_password = user[4]
            is_password_match = False
            
            # Cek apakah password terenkripsi atau tidak
            try:
                decrypted_password = decrypt_password(stored_password)
                is_password_match = (decrypted_password == _password)
            except:
                # Jika dekripsi gagal, asumsikan password disimpan dalam plain text
                is_password_match = (stored_password == _password)
            
            if is_password_match:
                session['logged_in'] = True
                session['username'] = _username
                session['role'] = user[5]  # Assuming role is the 5th column
                print(f"Logged in as: {session['username']}, Role: {session['role']}")  # Debugging line
                if user[5] == 'admin':
                    return redirect(url_for('admin_page'))
                else:
                    return redirect(url_for('decrypt_page'))
            else:
                flash('Invalid username or password', 'error')
        else:
            flash('Invalid username or password', 'error')
        
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        _username = request.form['username']
        _email = request.form['email']
        _password = request.form['password']
        
        encrypted_password = encrypt_password(_password)
        
        default_role = 'user'
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)", 
                    (_username, _email, encrypted_password, default_role))
        mysql.connection.commit()
        cur.close()
        
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_page():
    if request.method == 'POST':
        form_data = {
            'Nama': request.form['username'],
            'Email': request.form['email'],
            'No Handphone': request.form['handphone'],
            'Password': request.form['password'],
            'Tanggal lahir': request.form['tanggal_lahir'],
            'Jenis Kelamin': request.form['jenis_kelamin'],
            'Alamat': request.form['alamat'],
            'Riwayat Penyakit': request.form['riwayat_penyakit']
        }
        
        default_role = 'user'
        
        # Encrypt form data
        encrypted_data = encrypt_data(form_data)
        
        # Save user to database
        encrypted_password = encrypt_password(form_data['Password'])
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, email, handphone, password, role) VALUES (%s, %s, %s, %s, %s)", 
                    (form_data['Nama'], form_data['Email'], form_data['No Handphone'], encrypted_password, default_role))
        mysql.connection.commit()
        cur.close()
        
        flash('User added successfully and form data encrypted.', 'success')
        
        # Prepare encrypted data for download as .txt file
        encrypted_buffer = BytesIO(encrypted_data.encode('utf-8'))
        encrypted_filename = f"Encrypted_Rekam_Medis_{form_data['Nama'].replace(' ', '_')}.txt"
        
        # Prepare WhatsApp message
        whatsapp_message = f"Halo {form_data['Nama']}, ini adalah pesan otomatis dari sistem rekam medis kami. Berikut adalah informasi login Anda:\n\nUsername: {form_data['Nama']}\nPassword: {form_data['Password']}\n\nSilakan jaga kerahasiaan informasi ini. Terima kasih!"
        
        # Prepare WhatsApp URL
        whatsapp_url = f"https://wa.me/{form_data['No Handphone']}?text={urllib.parse.quote(whatsapp_message)}"
        
        # Send file and redirect to WhatsApp
        response = send_file(
            encrypted_buffer,
            as_attachment=True,
            download_name=encrypted_filename,
            mimetype='text/plain'
        )
        
        # Set a custom header to trigger JavaScript redirect
        response.headers['X-Redirect-WhatsApp'] = whatsapp_url
        
        return response
    
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_page():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file:
            try:
                # Read and decrypt the file content
                encrypted_content = file.read().decode('utf-8')
                decrypted_data = decrypt_data(encrypted_content)
                
                # Generate PDF from decrypted data
                pdf_buffer = generate_pdf(json.loads(decrypted_data))
                
                # Return the PDF file
                return send_file(
                    pdf_buffer,
                    as_attachment=True,
                    download_name="Decrypted_Rekam_Medis.pdf",
                    mimetype='application/pdf'
                )
            except Exception as e:
                flash(f'Error decrypting file: {str(e)}', 'error')
                return redirect(request.url)
    
    return render_template('decrypt.html')

# Function to encrypt existing admin password
def encrypt_admin_password():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE role = 'admin'")
    admin = cur.fetchone()
    
    if admin:
        stored_password = admin[3]
        try:
            # Coba dekripsi untuk memeriksa apakah sudah terenkripsi
            decrypt_password(stored_password)
            print("Admin password is already encrypted.")
        except:
            # Jika gagal dekripsi, asumsikan belum terenkripsi dan lakukan enkripsi
            encrypted_password = encrypt_password(stored_password)
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (encrypted_password, admin[0]))
            mysql.connection.commit()
            print("Admin password encrypted successfully.")
    else:
        print("Admin not found.")
    
    cur.close()

if __name__ == "__main__":
    with app.app_context():
        
        app.run(debug=True)