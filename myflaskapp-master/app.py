from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
import couchdb
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
couch = couchdb.Server()
# Using Database
db = couch['events']


# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Events
@app.route('/events')
def events():
    # Create cursor
    det = []
    events = []
    for a in db:
        det.append(db[a])
    for a in range(len(det)):
        if det[a]['type'] == 'event':
            events.append(det[a])
    if (len(events) > 0):
        return render_template('events.html', events=events)
    msg = 'No Events Found'
    return render_template('events.html', msg=msg)


# Single Event
@app.route('/event/<string:id>/')
def event(id):
    det = []
    event = []
    for a in db:
        det.append(db[a])
    for a in range(len(det)):
        if det[a]['type'] == 'event' and det[a]['_id'] == id:
            event.append(det[a])
    return render_template('event.html', event=event)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        doc = {'name': name, 'email': email, 'username': username, 'password': password, 'type': 'user'}
        db.save(doc)

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

        det = []
        for a in db:
            det.append(db[a])
        for a in range(len(det)):
            if det[a]['type'] == 'user':
                if det[a]['username'] == username and sha256_crypt.verify(password_candidate, det[a]['password']):
                    session['logged_in'] = True
                    session['username'] = username
                    flash('You are now logged in', 'success')
                    return redirect(url_for('dashboard'))
        error = 'Invalid login'
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


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    det = []
    events = []
    for a in db:
        det.append(db[a])
    for a in range(len(det)):
        if det[a]['type'] == 'event':
            events.append(det[a])
            return render_template('dashboard.html', events=events)
        msg = 'No Events Found'
        return render_template('dashboard.html', msg=msg)


# Event Form Class
class EventForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])


# Add Event
@app.route('/add_event', methods=['GET', 'POST'])
@is_logged_in
def add_event():
    form = EventForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        doc = {'title': title, 'body': body, 'username': session['username'], 'type': 'event'}
        db.save(doc)
        flash('Event Created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_event.html', form=form)


# Edit Event
@app.route('/edit_event/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_event(id):
    flash('Edit operation currently does not work')


"""
    # Create cursor
    cur = mysql.connection.cursor()

    # Get event by id
    result = cur.execute("SELECT * FROM events WHERE id = %s", [id])

    event = cur.fetchone()
    cur.close()
    # Get form
    form = EventForm(request.form)

    # Populate event form fields
    form.title.data = event['title']
    form.body.data = event['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']t

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(title)
        # Execute
        cur.execute("UPDATE events SET title=%s, body=%s WHERE id=%s", (title, body, id))
        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Event Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_event.html', form=form)
"""


# Delete Event
@app.route('/delete_event/<string:id>', methods=['POST'])
@is_logged_in
def delete_event(id):
    flash('Edit operation currently does not work')


"""
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM events WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Event Deleted', 'success')

    return redirect(url_for('dashboard'))
"""

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
