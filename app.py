from flask import Flask, render_template, request, redirect
from flask_mysqldb import MySQL

app = Flask(__name__)

# #konfigurasi mysql
# mysql = MySQL()
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = ''
# app.config['MYSQL_DB'] = 'uts_pemrograman'
# app.config['MYSQL_HOST'] = 'localhost'

# #port
# app.config['MYSQL_PORT'] = 3306


app.config['MYSQL_HOST'] = 'localhost'       # Alamat host (TCP/IP)
app.config['MYSQL_USER'] = 'root'            # Username MySQL
app.config['MYSQL_PASSWORD'] = ''  # Password MySQL
app.config['MYSQL_DB'] = 'uts_pemrograman'     # Nama database
app.config['MYSQL_PORT'] = 3306              # Port MySQL (default 3306)

mysql = MySQL(app)


#rooting
@app.route('/', methods=['GET','POST']) 
def signIn():
    if request.method == 'POST' : #simpan data
       _username = request.values.get('username')
       _email = request.values.get('email')
       _password = request.values.get('password')
       
       sql = "insert into users(name,email , password) values(%s, %s, %s)"
       data = (_username, _email, _password)
       
       cur = mysql.connection.cursor()
       cur.execute(sql, data)
       cur = mysql.connection.commit()
       
       
       return redirect('/home.html')
   
    else:
        return render_template('index.html')
    
@app.route('/home.html')
def home():
    return render_template('home.html')
    

if __name__ == "__main__":
    app.run(debug = True)