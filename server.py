from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re, datetime
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "sephiroth"

# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    if 'loggedIn' not in session:
        session['loggedIn'] = False
    else:
        session['loggedIn'] = True
    return render_template('index.html', **session)

@app.route('/register', methods=['POST'])
def register():
    # validattion check for First Name
    if len(request.form['first_name']) < 1:
        flash('First Name is required', 'first_name')
    elif not request.form['first_name'].isalpha():
        flash("Only use alphabets in first name")

    # validattion check for Last Name
    if len(request.form['last_name']) < 1:
        flash('Last Name is required', 'last_name')
    elif not request.form['last_name'].isalpha():
        flash("Only use alphabets in last name")

    # validattion check for email
    if len(request.form['email']) < 1:
        flash('Email is required', 'email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Email is Invalid', 'email')
    else:
        query = 'SELECT * FROM users WHERE email = %(email)s'
        data = {'email': request.form['email'] }
        mysql = connectToMySQL('walldb')
        result = mysql.query_db(query, data)

    # validation for password
    if len(request.form['password']) < 1:
        flash('Password is required', 'password')
    elif len(request.form['password']) < 8:
        flash('Password must be at least 8 characters', 'password')
    elif not re.search('[0-9]', request.form['password']):
        flash('Password must have at least one number', 'password')
    elif not re.search('[A-Z]', request.form['password']):
        flash('Password must have at least one capital letter', 'password')
    elif request.form['password'] != request.form['confirm_password']:
        flash('Passwords did not match', 'confirm_password')


    if '_flashes' in session.keys():
        # pass form data to sessions
        session['first_name'], session['last_name'], session['email']= request.form['first_name'], request.form['last_name'], request.form['email']
        return redirect('/')

    else: # No validation error so insert data to the database
        # create an hash password
        pw_hash = bcrypt.generate_password_hash(request.form['password'])

        # get data from the form
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'].strip().lower() ,
            'password': pw_hash
        }

        # connect to my Database and run insert query
        mysql = connectToMySQL('walldb')
        query = 'INSERT INTO users (first_name, last_name, email, password,created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW() )'

        session['user_id'] = mysql.query_db(query, data)
        return redirect('/home')

@app.route('/login', methods=['POST'])
def login():
    # check if this is a POST request
    if request.method != 'POST':
        session.clear()
        return redirect('/')

    # get the form data
    data = { 'email': request.form['email'].strip().lower() }
    query = 'SELECT * FROM users WHERE email = %(email)s'
    mysql = connectToMySQL('walldb')
    result = mysql.query_db(query, data)

    if len(result) > 0:
        user = result[0]
        if bcrypt.check_password_hash(user['password'], request.form['password']):
            session['user_id'] = user['id']
            session['loggedIn'] = True
            return redirect('/home')

    flash(' Your Log-In information was incorrect', 'login')
    return redirect('/')

@app.route('/home')
def home():
    if 'user_id' not in session:
        session.clear()
        return redirect('/')

    if session['loggedIn'] == False:
        session.clear()
        return redirect('/')

    # Get the user information from the database
    data = {'id': session['user_id']}
    query = """SELECT users.first_name AS first_name,
                users2.first_name AS sender_name,
                messages.id AS message_id,
                messages.content AS messages,
                messages.sender_id AS sender_id,
                messages.recipient_id AS recipient_id,
                messages.created_at AS created_at
                FROM users
                LEFT JOIN messages ON messages.recipient_id = users.id
                LEFT JOIN users AS users2 ON users2.id = messages.sender_id
                WHERE users.id = %(id)s;"""
    mysql = connectToMySQL('walldb')
    messages_data = mysql.query_db(query, data)


    # get the user info from the DB
    query = 'SELECT first_name FROM users WHERE id = %(id)s;'
    data = {'id': session['user_id']}
    mysql = connectToMySQL('walldb')
    user = mysql.query_db(query, data)

    # Get the list of users except the logged in user
    mysql = connectToMySQL('walldb')
    query = 'SELECT id AS recipient_id, first_name AS recipient_name FROM users WHERE id <> %(id)s;'
    other_users = mysql.query_db(query, data)
    print(messages_data)

    SELECT COUNT(*) as count from messages where reciever_id = %(id)s
    countUsers = mysql.query_db(query, data)

    SELECT COUNT(*) as count from messages where sender_id = %(id)s
    countMessages = mysql.query_db(query, data)


    return render_template('home.html', user=user[0], other_users=other_users, messages_data=messages_data, countUsers = countUsers[0]['count'], countMessages = countMessages[0]['count'])


@app.route('/send_message', methods=['POST'])
def send():
    # record data from form
    data = {
        'message': request.form['message'],
        'sender_id': session['user_id'],
        'recipient_id': request.form['recipient_id']
    }
    query = 'INSERT INTO messages(content, sender_id, recipient_id, created_at, updated_at) VALUES (%(message)s, %(sender_id)s, %(recipient_id)s, NOW(),NOW());'
    mysql = connectToMySQL('walldb')
    mysql.query_db(query, data)
    return redirect('/home')

@app.route('/delete/<id>')
def delete(id):
    if 'user_id' not in session:
        session.clear()
        return redirect('/')

    data = {'id': id}
    mysql = connectToMySQL('walldb')
    query = 'DELETE FROM messages WHERE id = %(id)s'
    mysql.query_db(query, data)
    return redirect('/home')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__=="__main__":
    app.run(debug=True)
