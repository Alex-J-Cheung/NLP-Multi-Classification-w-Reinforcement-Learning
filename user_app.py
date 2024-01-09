#!/usr/bin/env python
# coding: utf-8

# # Setting up SQL database

# In[1]:


import sqlite3
import bcrypt
import uuid

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Connect to SQLite Database
conn = sqlite3.connect('users.db')
cur = conn.cursor()

# Create and update tables
cur.execute('''
    CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role_id TEXT,
        failed_attempts INTEGER DEFAULT 0,
        block_until DATETIME,
        last_login DATETIME,
        FOREIGN KEY (role_id) REFERENCES roles (id)
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS user_profiles (
        user_id TEXT,
        email TEXT UNIQUE,
        full_name TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

cur.execute('''
    CREATE TABLE IF NOT EXISTS password_resets (
        user_id TEXT,
        reset_token TEXT,
        requested_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

# Insert default roles with UUIDs
roles = [(str(uuid.uuid4()), 'admin'), (str(uuid.uuid4()), 'user')]
cur.executemany('INSERT OR IGNORE INTO roles (id, name) VALUES (?, ?)', roles)

# Add an example admin user with UUID
admin_password = hash_password("admin123")
admin_role_id = cur.execute('SELECT id FROM roles WHERE name = "admin"').fetchone()[0]
cur.execute('INSERT OR IGNORE INTO users (id, username, password, role_id) VALUES (?, ?, ?, ?)', (str(uuid.uuid4()), 'admin', admin_password, admin_role_id))

# Commit the changes and close the connection
conn.commit()
conn.close()


# # Streamlit Application

# In[ ]:


import streamlit as st
import bcrypt
import sqlite3
import re
import datetime
import uuid

# Connect to the SQLite database
def connect_db():
    return sqlite3.connect('users.db')

# Hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Check hashed password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# Validate username
def validate_username(username):
    if not 3 <= len(username) <= 15:
        return False
    if not re.match("^[a-zA-Z0-9_]*$", username):
        return False
    return True

# Create a new user
def create_user(username, password):
    if not validate_username(username):
        st.error("Invalid username format.")
        return False

    try:
        conn = connect_db()
        cur = conn.cursor()
        # Check if username already exists
        cur.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cur.fetchone():
            st.error("Username already exists.")
            return False

        # Insert new user
        hashed_password = hash_password(password)
        user_id = str(uuid.uuid4())
        cur.execute('INSERT INTO users (id, username, password) VALUES (?, ?, ?)', (user_id, username, hashed_password))
        conn.commit()
        return True
    except Exception as e:
        st.error("An error occurred while creating the user.")
        print(e)
    finally:
        conn.close()
    return False

# Authenticate user and update last login
def authenticate_user(username, password):
    if not validate_username(username):
        return False

    try:
        conn = connect_db()
        cur = conn.cursor()
        cur.execute('SELECT id, password, failed_attempts, block_until FROM users WHERE username = ?', (username,))
        user_data = cur.fetchone()

        if user_data:
            user_id, hashed_password, failed_attempts, block_until = user_data

            if block_until and datetime.datetime.now() < datetime.datetime.fromisoformat(block_until):
                st.error("Account is temporarily blocked due to multiple failed login attempts. Please try again later.")
                return False

            if check_password(hashed_password, password):
                cur.execute('UPDATE users SET last_login = ?, failed_attempts = 0, block_until = NULL WHERE id = ?', (datetime.datetime.now().isoformat(), user_id))
                conn.commit()
                return True
            else:
                update_failed_attempts(username, failed_attempts, cur)
                conn.commit()
        else:
            st.error("Invalid username.")
    except Exception as e:
        st.error("An error occurred while accessing the database.")
        print(e)
    finally:
        conn.close()

    return False

def update_failed_attempts(username, failed_attempts, cur):
    failed_attempts += 1
    if failed_attempts >= 3:  # Threshold for failed attempts
        block_time = datetime.datetime.now() + datetime.timedelta(minutes=5)  # Block for 5 minutes
        cur.execute('UPDATE users SET failed_attempts = ?, block_until = ? WHERE username = ?', (failed_attempts, block_time.isoformat(), username))
    else:
        cur.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (failed_attempts, username))

# UI for registration
def registration_form():
    with st.form("register_form"):
        new_username = st.text_input("Choose a Username")
        new_password = st.text_input("Choose a Password", type='password')
        submit_button = st.form_submit_button("Register")

        if submit_button:
            if create_user(new_username, new_password):
                st.success("User created successfully. Please login.")
                st.session_state.registration_success = True
            else:
                st.error("Failed to create user.")

# Initialize session state for registration success
if 'registration_success' not in st.session_state:
    st.session_state.registration_success = False

# UI
st.title('User Authentication and Registration')

# Registration form
if st.checkbox("Register New Account", not st.session_state.registration_success):
    registration_form()

# Login form
elif 'authenticated' in st.session_state and st.session_state.authenticated:
    st.write(f"Welcome, {st.session_state.username}! You're logged in.")
    if st.button('Logout'):
        st.session_state.authenticated = False
        st.session_state.registration_success = False
else:
    username = st.sidebar.text_input('Username')
    password = st.sidebar.text_input('Password', type='password')

    if st.sidebar.button('Login'):
        if authenticate_user(username, password):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.success(f'Welcome, {username}! You are successfully logged in!')
        else:
            st.error('Invalid login credentials or username format.')

