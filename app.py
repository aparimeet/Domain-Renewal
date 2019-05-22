from flask import Flask, render_template, flash, redirect, url_for, session, request, logging

from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'domainrenewal'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)

# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')



# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=100)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')
    phonenumber = StringField('Phone number', [validators.Length(min=1, max=50)])
    birthdate = StringField('Date of Birth (YYYY-MM-DD)', [validators.Length(min=1, max=50)])
    religion = StringField('Religion', [validators.Length(min=3, max=50)])
    gender = StringField('Gender', [validators.Length(min=1, max=50)])
    address = StringField('Address', [validators.Length(min=1, max=100)])


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        phonenumber = form.phonenumber.data
        birthdate = form.birthdate.data
        religion = form.religion.data
        gender = form.gender.data
        address = form.address.data

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password, phonenumber, birthdate, religion, gender, address) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)", (name, email, username, password, phonenumber, birthdate, religion, gender, address))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# Purchase Domain Form Class
class PurchaseDomainForm(Form):
    domainname = StringField('Domain Name', [validators.Length(min=5, max=50)])
    amount = StringField('Amount', [validators.Length(min=4, max=25)])
    purchasedate = StringField('Purchase Date', [validators.Length(min=6, max=50)])


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    cur = mysql.connection.cursor()

   
    # Close connection
    cur.close()
    return render_template('dashboard.html')



if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
