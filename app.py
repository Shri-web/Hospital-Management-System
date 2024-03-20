from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_session import Session
import os
import sqlite3
import bcrypt
import re
import requests
import pyotp
import os
from dotenv import load_dotenv


load_dotenv()
secret_key = os.getenv('SECRET_KEY')

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"


Session(app)

DATABASE = 'hospital.db'  # Update with your database file

# Function to connect to the SQLite database
def connect_db():
    return sqlite3.connect(DATABASE)

# Initialize the database schema and admin user if not exists
def initialize_db():
    conn = connect_db()
    cursor = conn.cursor()

    # Create the 'users' table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Create a table for administrators
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS administrators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    # Create a table for doctors
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            specialty TEXT,
            contact_number TEXT
        )
    ''')

    # Create a table for nurses
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nurses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            department TEXT,
            contact_number TEXT
        )
    ''')

    # Create a table for patients
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            date_of_birth DATE,
            contact_number TEXT,
            address TEXT,
            medical_history TEXT
        )
    ''')

    # Create a table for patient assignments (Doctors)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctor_assignments (
            id INTEGER PRIMARY KEY,
            patient_id INTEGER,
            doctor_id INTEGER,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (doctor_id) REFERENCES doctors(id)
        );
    ''')

    # Create a table for patient assignments (Nurse)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nurse_assignments (
            id INTEGER PRIMARY KEY,
            patient_id INTEGER,
            nurse_id INTEGER,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (nurse_id) REFERENCES nurses(id)
        );
    ''')

    # Check if an admin user already exists
    cursor.execute("SELECT * FROM users WHERE username=?", ('admin',))
    admin_user = cursor.fetchone()

    if not admin_user:
        admin_username = "admin"
        admin_password = "admin"  # Replace with a secure password
        hashed_admin_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())

        # Insert the admin user into the 'users' table
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (admin_username, hashed_admin_password, 'Administrator'))

        # Commit the changes
        conn.commit()

    conn.close()

# Initialize the database on startup
initialize_db()

def verify_recaptcha(recaptcha_response):
    data = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    return result.get('success', False)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not verify_recaptcha(recaptcha_response):
            flash('reCAPTCHA verification failed. Please try again.', category='error')
            error_message = "Incorrect reCAPTCHA. Please try again."
            return render_template('login.html', error_message=error_message)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Check if a user with the given username exists
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if user is not None:
            # User found, check the password
            stored_password = user[2]  # The password is already stored as bytes
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Passwords match, log the user in
                session['user_id'] = user[0]  # Assuming the user ID is at index 0
                session['username'] = user[1]
                session['role'] = user[3]  # Assuming the role field is at index 3

                # Redirect to the appropriate dashboard based on the user's role
                if session['role'] == 'Administrator':
                    session['role'] = ''
                    return redirect(url_for('admin_2fa'))
                elif session['role'] == 'Doctor':
                    return redirect(url_for('doctor_dashboard'))
                elif session['role'] == 'Nurse':
                    return redirect(url_for('nurse_dashboard'))
                elif session['role'] == 'Patient':
                    return redirect(url_for('patient_dashboard'))
            else:
                error_message = "Incorrect username or password."
        else:
            error_message = "Incorrect username or password."

        conn.close()

    return render_template('login.html', error_message=error_message)

@app.route('/admin_2fa', methods=['GET', 'POST'])
def admin_2fa():
    if request.method == 'POST':
        otp = request.form['otp']

        topt = pyotp.totp.TOTP('ZZNIRYUFMDP5CY2LHSCLDGHO3TAMB7Y2')
        current_otp = topt.now()

        if otp != current_otp:
            flash('Incorrect OTP. Please try again.', category='error')
            return render_template('admin_2fa.html')
        else:
            session['role'] = 'Administrator'
            return redirect(url_for('admin_dashboard'))

    return render_template('admin_2fa.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    role = session.get('role')

    dashboard_templates = {
        'Administrator': 'admin_dashboard.html',
        'Doctor': 'doctor_dashboard.html',
        'Nurse': 'nurse_dashboard.html',
        'Patient': 'patient_dashboard.html',
    }

    if role in dashboard_templates:
        return render_template(dashboard_templates[role])
    else:
        # Handle unknown or unauthorized roles
        return "Unauthorized Access", 403  # HTTP 403 Forbidden

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'Administrator':
        return redirect(url_for('login'))

    # Add your code to fetch and display relevant information for the admin here

    return render_template('admin_dashboard.html')

@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'user_id' not in session or session['role'] != 'Doctor':
        return redirect(url_for('login'))

    # Add your code to fetch and display relevant information for doctors here

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT patients.full_name, patients.date_of_birth, patients.contact_number, patients.address, patients.medical_history
        FROM doctor_assignments 
        INNER JOIN doctors ON doctor_assignments.doctor_id = doctors.id 
        INNER JOIN patients ON doctor_assignments.patient_id = patients.id
        WHERE doctors.username = ?
    ''', (session['username'],))

    patients_res = cursor.fetchall()

    patients = []
    for patient in patients_res:
        patients.append({
            'name': patient[0],
            'date_of_birth': patient[1],
            'contact_number': patient[2],
            'address': patient[3],
            'medical_history': patient[4]
        })
        
    # Fetch nurse details from the 'nurses' table
    cursor.execute("SELECT full_name, department, contact_number FROM nurses")
    nurses_res = cursor.fetchall()

    nurses = []

    for nurse in nurses_res:
        nurses.append({
            'name': nurse[0],
            'department': nurse[1],
            'contact_number': nurse[2]
        })


    conn.close()

    return render_template('doctor_dashboard.html', patients=patients, nurses=nurses)

@app.route('/nurse_dashboard')
def nurse_dashboard():
    if 'user_id' not in session or session['role'] != 'Nurse':
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT patients.full_name, patients.date_of_birth, patients.contact_number, patients.address, patients.medical_history
        FROM nurse_assignments 
        INNER JOIN nurses ON nurse_assignments.nurse_id = nurses.id 
        INNER JOIN patients ON nurse_assignments.patient_id = patients.id
        WHERE nurses.username = ?
    ''', (session['username'],))

    patients_res = cursor.fetchall()

    patients = []
    for patient in patients_res:
        patients.append({
            'name': patient[0],
            'date_of_birth': patient[1],
            'contact_number': patient[2],
            'address': patient[3],
            'medical_history': patient[4]
        })
    
    # Fetch doctor details from the 'doctors' table
    cursor.execute("SELECT full_name, specialty, contact_number FROM doctors")
    doctors_res = cursor.fetchall()

    doctors = []

    for doctor in doctors_res:
        doctors.append({
            'name': doctor[0],
            'specialty': doctor[1],
            'contact_number': doctor[2]
        })

    conn.close()

    return render_template('nurse_dashboard.html', patients=patients, doctors=doctors)

@app.route('/patient_dashboard')
def patient_dashboard():
    if 'user_id' not in session or session['role'] != 'Patient':
        return redirect(url_for('login'))

    # Add your code to fetch and display relevant information for patients here
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    doctors = []
    nurses = []

    cursor.execute('''
        SELECT doctors.full_name, doctors.specialty, doctors.contact_number
        FROM doctor_assignments 
        INNER JOIN doctors ON doctor_assignments.doctor_id = doctors.id 
        INNER JOIN patients ON doctor_assignments.patient_id = patients.id
        WHERE patients.username = ?
    ''', (session['username'],))
    doctors_res = cursor.fetchall()

    for doctor in doctors_res:
        doctors.append({
            'name': doctor[0],
            'specialty': doctor[1],
            'contact_number': doctor[2]
        })

    cursor.execute('''
        SELECT nurses.full_name, nurses.department, nurses.contact_number
        FROM nurse_assignments
        INNER JOIN nurses ON nurse_assignments.nurse_id = nurses.id
        INNER JOIN patients ON nurse_assignments.patient_id = patients.id
        WHERE patients.username = ?
    ''', (session['username'],))
    nurses_res = cursor.fetchall()
    
    for nurse in nurses_res:
        nurses.append({
            'name': nurse[0],
            'department': nurse[1],
            'contact_number': nurse[2]
        })

    conn.close()

    return render_template('patient_dashboard.html', doctors=doctors, nurses=nurses)

@app.route('/assign-doctor', methods=['POST'])
def assign_doctor():
    doctor_id = request.form['doctor_id']
    patient_id = request.form['patient_id']

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO doctor_assignments (patient_id, doctor_id) VALUES (?, ?)", (patient_id, doctor_id))

    conn.commit()
    conn.close()

    return redirect(url_for('admin'))

@app.route('/assign-nurse', methods=['POST'])
def assign_nurse():
    nurse_id = request.form['nurse_id']
    patient_id = request.form['patient_id']

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO nurse_assignments (patient_id, nurse_id) VALUES (?, ?)", (patient_id, nurse_id))

    conn.commit()
    conn.close()
    
    return redirect(url_for('admin'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or session['role'] != 'Administrator':
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']

        # Password requirements
        results = re.search(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", new_password)
        if results == None:
            flash('Password should be of minimum eight characters, at least one letter, one number and one special character')
            return render_template('admin.html')
        
        # Contact number checks
        cn = request.form['contact_number']
        if cn == None or len(cn) != 10:
            flash('Needed a valid contact number')
            return render_template('admin.html')

        role = request.form['role']

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (new_username, hashed_password, role))

            if role == 'Doctor':
                # Handle adding a doctor to the doctors table
                full_name = request.form['full_name']
                specialty = request.form['specialty']
                contact_number = request.form['contact_number']
                cursor.execute("INSERT INTO doctors (username, password, full_name, specialty, contact_number) VALUES (?, ?, ?, ?, ?)",
                               (new_username, hashed_password, full_name, specialty, contact_number))
            elif role == 'Nurse':
                # Handle adding a nurse to the nurses table
                full_name = request.form['full_name']
                department = request.form['department']
                contact_number = request.form['contact_number']
                cursor.execute("INSERT INTO nurses (username, password, full_name, department, contact_number) VALUES (?, ?, ?, ?, ?)",
                               (new_username, hashed_password, full_name, department, contact_number))
            elif role == 'Patient':
                # Handle adding a patient to the patients table
                full_name = request.form['full_name']
                date_of_birth = request.form['date_of_birth']
                contact_number = request.form['contact_number']
                address = request.form['address']
                medical_history = request.form['medical_history']
                cursor.execute("INSERT INTO patients (username, password, full_name, date_of_birth, contact_number, address, medical_history) VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (new_username, hashed_password, full_name, date_of_birth, contact_number, address, medical_history))

            conn.commit()

    doctors = []
    nurses = []
    patients = []

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, full_name, specialty FROM doctors")
        doctors_res = cursor.fetchall()

        for doctor in doctors_res:
            doctors.append({
                'id': doctor[0],
                'name': doctor[1] + '-' + doctor[2],
            })

        cursor.execute("SELECT id, full_name FROM nurses")
        nurses_res = cursor.fetchall()

        for nurse in nurses_res:
            nurses.append({
                'id': nurse[0],
                'name': nurse[1]
            })


        cursor.execute("SELECT id, full_name FROM patients")
        patients_res = cursor.fetchall()
        for patient in patients_res:
            patients.append({
                'id': patient[0],
                'name': patient[1]
            })

    return render_template('admin.html', doctors=doctors, nurses=nurses, patients=patients)

@app.route('/user_details', methods=['GET', 'POST'])
def user_details():
    if 'user_id' in session and session['role'] == 'Administrator':
        conn = sqlite3.connect('hospital.db')
        cursor = conn.cursor()

        # Fetch user details from the 'patients' table
        cursor.execute("SELECT full_name, date_of_birth, contact_number, address, medical_history FROM patients")
        patients = cursor.fetchall()

        patients_list = []
        for patient in patients:
            patients_list.append({
                'name': patient[0],
                'date_of_birth': patient[1],
                'contact_number': patient[2],
                'address': patient[3],
                'medical_history': patient[4]
            })

        # Fetch user details from the 'doctors' table
        cursor.execute("SELECT full_name, specialty, contact_number FROM doctors")
        doctors = cursor.fetchall()

        doctors_list = []
        for doctor in doctors:
            doctors_list.append({
                'name': doctor[0],
                'specialty': doctor[1],
                'contact_number': doctor[2]
            })

        # Fetch user details from the 'nurses' table
        cursor.execute("SELECT full_name, department, contact_number FROM nurses")
        nurses = cursor.fetchall()

        nurses_list = []
        for nurse in nurses:
            nurses_list.append({
                'name': nurse[0],
                'department': nurse[1],
                'contact_number': nurse[2]
            })

        conn.close()

        return render_template('users_table.html', patients=patients_list, doctors=doctors_list, nurses=nurses_list)

    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))    

if __name__ == '__main__':
    app.run(debug=True)

