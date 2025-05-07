from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from models import db_session, User, UserRole, FormB, FormC
from utils.helpers import generate_reset_token, send_email, validate_password
import os
import secrets
from dotenv import load_dotenv
import uuid
from datetime import datetime, timedelta, timezone
from flask_cors import CORS

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app) 

app.secret_key = os.getenv('SECRETE_KEY')

@app.route('/api')
def index():
    response={
         "message": "Welocme",
    }
    return jsonify(response), 200

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        user_password = request.form.get('password')
        user = db_session.query(User).filter_by(email=email).first()

        print(user_password)
        print(email)
        print(user.verify_password(password=user_password))
        if user and user.verify_password(user_password):
            session['loggedin'] = True
            session['id'] = user.user_id
            session['name'] = user.full_name

            # render appropriate template depending on role
            # NB: role is an enum, hence the .value
            role = user.role.value or 'student'
            
            if role == 'student':
                # return render_template('video.html')
                return render_template('dashboard.html') # Render video page if not completed yet.
            elif role == 'supervisor':
                return render_template('supervisor-dashboard.html')
            elif role == 'admin':
                return render_template('admin-dashboard.html')
            elif role == 'rec':
                return render_template('committee-dashboard.html')
            elif role == 'dean':
                return render_template('dean-dashboard.html')
            else:
                return render_template( 'video.html') #default fallback 
        else:
            error = 'Incorrect email or password'
            return render_template('login.html', msg=error)

    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['loggedin'] = False
    session['id'] = ""
    session['name'] = ""
    return render_template('logout.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    data = request.form
    required_fields = ["full_name", "student_number", "email", "password", "supervisor_id"]
   
    if request.method == 'POST' and all(key in data for key in required_fields):
        full_name = data['full_name'].strip()  # Todo : Capitalize letters of first name and last name
        student_number = data['student_number']
        email = data['email'].strip().lower()
        password = data['password']
        supervisor_id = data['supervisor_id']
        
        # validate UJ email
        if not email.endswith('student.uj.ac.za'):
            msg = "Only University of Johannesburg email allowed"
            return render_template('register.html', msg=msg )
        
        # validate password
        is_valid, message = validate_password(password) 
        if not is_valid:
            msg = message
            return render_template('register.html', msg=msg)
        
        user = db_session.query(User).filter_by(email=email).first()
        if user:
            msg = 'Email already registered!'
            return render_template('register.html', msg=msg)
        else:
            new_user = User(full_name=full_name, student_number=student_number, email=email, password=password, supervisor_id=supervisor_id, role=UserRole.STUDENT)
            
            db_session.add(new_user)
            db_session.commit()
            
            msg = 'You have successfully registered!'
    else:
        msg = ''
        return render_template('register.html', msg=msg)
    
    return render_template('login.html', msg=msg)


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email is required'}), 400

    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        # For security, don't reveal if the email exists
        return jsonify({'message': 'If that email exists, a reset link has been sent.'}), 200

    # Generate token and expiry
    token = generate_reset_token()
    user.reset_token = token
    user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
    session.commit()

    # Send email to user with the token
    try:
        send_email("motsietsepang@gmail.com", "UJ Ethics System: Password Resset", token)
    except:
        print("Error in ['/api/forgot-password'] ", "password reset token email sending failed.")
        return jsonify({'message': 'Server failed to send email. Contact admin.'}), 500

    return jsonify({'message': 'If that email exists, a reset code has been sent.'}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({'message': 'Token and new password are required'}), 400

    user = session.query(User).filter_by(reset_token=token).first()
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.now(timezone.utc):
        return jsonify({'message': 'Invalid or expired token'}), 400
    
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({'message': message}), 400

    # Update password
    user.password = User.hash_password(new_password)
    user.reset_token = None
    user.reset_token_expiry = None
    session.commit()

    return jsonify({'message': 'Password has been reset successfully.'}), 200

@app.route('/api/supervisors', methods=['GET'])
def get_supervisors():
    supervisors = db_session.query(User).filter(User.role == UserRole.SUPERVISOR).all()
    
    # Convert to list of dicts
    result = [
        {
            "user_id": sup.user_id,
            "full_name": sup.full_name,
            "email": sup.email
        }
        for sup in supervisors
    ]
    
    return jsonify(result), 200

# =====================================================================================================
# THIS SECTION IS FOR HANDLING FORMS
# =====================================================================================================

# FORM A =====================================================================================================





# FORM B =====================================================================================================
@app.route('/api/form-b/<form_id>', methods=['GET'])
def get_form_b(form_id):
    form_b = db_session.query(FormB).filter_by(form_id=form_id).first()
    if not form_b:
        return jsonify({"message": "Form not found"}), 404
    return jsonify(form_b.to_dict()), 200



@app.route('/api/form-b', methods=['POST'])
def submit_form_b():
    data = request.get_json()
    required_fields = [
        "applicant_name", "student_number", "institution", "department", "degree",
        "project_title", "mobile_number", "email_address", "supervisor_name",
        "supervisor_email", "declaration_full_name", "declaration_date"
    ]

    # Validate required fields
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    try:
        form_b = FormB(
            applicant_name=data["applicant_name"],
            student_number=data["student_number"],
            institution=data["institution"],
            department=data["department"],
            degree=data["degree"],
            project_title=data["project_title"],
            mobile_number=data["mobile_number"],
            email_address=data["email_address"],
            supervisor_name=data["supervisor_name"],
            supervisor_email=data["supervisor_email"],
            project_description=data.get("project_description"),
            data_nature=data.get("data_nature"),
            data_origin=data.get("data_origin"),
            data_public=data.get("data_public"),
            public_evidence=data.get("public_evidence"),
            access_conditions=data.get("access_conditions"),
            personal_info=data.get("personal_info"),
            data_anonymized=data.get("data_anonymized"),
            anonymization_comment=data.get("anonymization_comment"),
            private_permission=data.get("private_permission"),
            permission_details=data.get("permission_details"),
            shortcomings_reported=data.get("shortcomings_reported"),
            limitations_reporting=data.get("limitations_reporting"),
            methodology_alignment=data.get("methodology_alignment"),
            data_acknowledgment=data.get("data_acknowledgment"),
            original_clearance=data.get("original_clearance"),
            participant_permission=data.get("participant_permission"),
            data_safekeeping=data.get("data_safekeeping"),
            risk_level=data.get("risk_level"),
            risk_comments=data.get("risk_comments"),
            declaration_full_name=data["declaration_full_name"],
            declaration_date=datetime.strptime(data["declaration_date"], "%Y-%m-%d")
        )
        db_session.add(form_b)
        db_session.commit()
        return jsonify({"message": "Form B submitted successfully"}), 201
    except Exception as e:
        db_session.rollback()
        return jsonify({"message": f"Error: {str(e)}"}), 500
    

# FORM C =====================================================================================================
@app.route('/api/form-c', methods=['POST'])
def submit_form_c():
    data = request.get_json()
    required_fields = [
        "applicant_name", "student_number", "institution", "department", "degree",
        "project_title", "mobile_number", "email_address", "supervisor_name",
        "supervisor_email", "declaration_full_name", "declaration_date"
    ]

    # Validate required fields
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    try:
        form_c = FormC(
            applicant_name=data["applicant_name"],
            student_number=data["student_number"],
            institution=data["institution"],
            department=data["department"],
            degree=data["degree"],
            project_title=data["project_title"],
            mobile_number=data["mobile_number"],
            email_address=data["email_address"],
            supervisor_name=data["supervisor_name"],
            supervisor_email=data["supervisor_email"],
            ethical_clearance=data.get("ethical_clearance"),
            clearance_details=data.get("clearance_details"),
            participant_consent=data.get("participant_consent"),
            consent_details=data.get("consent_details"),
            risk_assessment=data.get("risk_assessment"),
            declaration_full_name=data["declaration_full_name"],
            declaration_date=datetime.strptime(data["declaration_date"], "%Y-%m-%d")
        )
        db_session.add(form_c)
        db_session.commit()
        return jsonify({"message": "Form C submitted successfully"}), 201
    except Exception as e:
        db_session.rollback()
        return jsonify({"message": f"Error: {str(e)}"}), 500
    

@app.route('/api/form-c/<form_id>', methods=['GET'])
def get_form_c(form_id):
    form_c = db_session.query(FormC).filter_by(form_id=form_id).first()
    if not form_c:
        return jsonify({"message": "Form not found"}), 404
    return jsonify(form_c.to_dict()), 200

# =====================================================================================================
# END OF FORMS
# =====================================================================================================

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))  
    app.run(host='0.0.0.0', port=port, debug=True)