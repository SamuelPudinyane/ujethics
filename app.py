from flask import Flask,flash,make_response, render_template, request, redirect, url_for, session, jsonify
from models import db_session, User, UserRole, UserInfo, FormA, FormB, FormC, FormD, FormUploads, Documents,FormARequirements,Watched
from utils.helpers import generate_reset_token, send_email, validate_password
import json
from db_queries import getFormAData, getSupervisorsList
import os
import io
import pdfkit
from werkzeug.utils import secure_filename
import secrets
from dotenv import load_dotenv
import uuid
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from datetime import date
from sqlalchemy import desc,cast ,Date
from sqlalchemy.orm import joinedload
from collections import defaultdict
from sqlalchemy import or_
from sqlalchemy import func

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__,static_folder='static')
CORS(app) 
csrf = CSRFProtect(app)
app.secret_key = os.getenv('SECRET_KEY')

###import dummy_data

###dummy_data

ALLOWED_EXTENSIONS = {'pdf', 'docx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api')
def index():
    response={
         "message": "Welocme",
    }
    return jsonify(response), 200


@app.route('/student-dashboard', methods=['GET'])
def student_dashboard():
    user_id=session.get('id')

    if not user_id:
        return "Unauthorized access. Please log in.", 401
    
    formA = db_session.query(FormA).filter_by(user_id=user_id).first()
    formB = db_session.query(FormB).filter_by(user_id=user_id).first()
    formC = db_session.query(FormC).filter_by(user_id=user_id).first()
    formD = db_session.query(FormD).filter_by(user_id=user_id).first()
  
    return render_template('dashboard.html',formA=formA,formB=formB,formC=formC,formD=formD)

@app.route('/quiz', methods=['GET'])
def quiz():
    return render_template('quiz.html')

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    
    
    if request.method == 'POST':
        email = request.form.get('email')
        user_password = request.form.get('password')
        email = request.form.get('email')
        user_password = request.form.get('password')
        user = db_session.query(User).filter_by(email=email).first()
       
        
        if user:
            if user.verify_password(user_password):
                session['loggedin'] = True
                session['id'] = user.user_id
                session['name'] = user.full_name

                # render appropriate template depending on role
                # NB: role is an enum, hence the .value
                role = user.role.value or 'student'
                
                if role == 'STUDENT':
                    #student_info = db_session.query(UserInfo).filter_by(user_id=session['id']).first()
                    user_id = session['id']
                    #if student_info and student_info.watched_demo and student_info.test_score is not None and student_info.test_score >= 80:
                    watched_video = db_session.query(Watched).filter_by(user_id=user_id).first()
                   
                    if watched_video:
                        return render_template('ethics_pack.html', name = session['name'])
                    else:
                        
                        return render_template('video.html')
                elif role == 'SUPERVISOR':
                    session['supervisor_role']='SUPERVISOR'
                    return redirect(url_for('supervisor_dashboard'))
                elif role == 'ADMIN':
                    session['admin_role']='ADMIN'
                    return redirect(url_for('chair_landing'))
                elif role == 'REC':
                    session['rec_role']='REC'
                    return redirect(url_for('rec_dashboard'))
                elif role == 'REVIEWER':
                    session['reviewer_role']='REVIEWER'
                    return redirect(url_for('review_dashboard'))
                elif role == 'DEAN':
                    session['dean_role']='DEAN'
                    return redirect(url_for('dean_dashboard'))
                else:
                    return render_template( 'video.html') #default fallback 
            else:
                error = 'Incorrect email or password'
                return render_template('login.html', messages=[error])
        else:
            error = 'Incorrect email or password'
            return render_template('login.html', messages=[error])

    return render_template('login.html')


@app.route('/api/register', methods=['GET', 'POST'])
def register():
    supervisors = db_session.query(User).filter(User.role == UserRole.SUPERVISOR).all()
    msg = {}
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        student_number = request.form.get('student_number', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        supervisor_id = request.form.get('supervisors')
        
        # Debug print to verify raw inputs
       
        # Validate UJ email
        if not email.endswith('student.uj.ac.za'):
            msg = "Only University of Johannesburg email allowed"
            return render_template('register.html', messages=[msg], supervisors=supervisors)

        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            msg['message'] = message
            return render_template('register.html', messages=msg, supervisors=supervisors)

        # Check if user exists
        user = db_session.query(User).filter_by(email=email).first()
        if user:
            msg = 'Email already registered!'
            return render_template('register.html', messages=[msg], supervisors=supervisors)
        
        try:
            # Hash the password properly
            
            
            # Create new user
            new_user = User(
                full_name=full_name,
                student_number=student_number,
                email=email,
                password=password,  # Make sure this is the hashed version
                supervisor_id=supervisor_id,
                role=UserRole.STUDENT
            )
            
            db_session.add(new_user)
            db_session.commit()
            
            # Debug: Verify what was stored
            stored_user = db_session.query(User).filter_by(email=email).first()
            
            msg = 'You have successfully registered!'
            return render_template("login.html", messages=[msg])
            
        except Exception as e:
            db_session.rollback()
            print("Registration error:", str(e))
            msg = 'Registration failed. Please try again.'
            return render_template('register.html', messages=[msg], supervisors=supervisors)
    
    msg = 'Please fill out the form completely!'
    return render_template('register.html', messages=[msg], supervisors=supervisors)



@app.route('/register_reviewer', methods=['GET', 'POST'])
def register_reviewer():
    
    messages=''
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        staff_number = request.form.get('staff_number', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        password2=request.form.get('password2').strip()
        specialisation = request.form.get('specialisation')
        role=request.form.get('role')
        if password == password2:

            # Validate password
            is_valid, message = validate_password(password)
            if not is_valid:
                return render_template('register_reviewer.html', messages=[message])

            # Check if user exists
            user = db_session.query(User).filter_by(email=email).first()
            if user:
                messages = 'Email already registered!'
                return render_template('register_reviewer.html', messages=[messages])
            
            try:
                # Hash the password properly
                
                # Create new user
                new_user = User(
                    full_name=full_name,
                    staff_number=staff_number,
                    email=email,
                    password=password,  # Make sure this is the hashed version
                    specialisation=specialisation,
                    role=role
                )
                
                db_session.add(new_user)
                db_session.commit()
                
                messages = 'You have successfully registered!'
                return redirect(url_for('reviewer_list'))
                
            except Exception as e:
                db_session.rollback()
                print("Registration error:", str(e))
                messages = 'Registration failed. Please try again.'
                return render_template('register_reviewer.html', messages=[messages])
        else:
            messages="Passwords mismatch"
            render_template('register_reviewer.html', messages=[messages])
    messages= 'Please fill out the form completely!'
    return render_template('register_reviewer.html', messages=[messages])

@app.route('/edit_user/<string:id>', methods=['POST','GET'])
def edit_user(id):
    user = db_session.query(User).filter_by(user_id=id).first()
    msg="update the user information"
    if user:
        full_name = request.form.get('full_name', '').strip()
        staff_number = request.form.get('staff_number', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        password2 = request.form.get('password2', '').strip()
        specialisation = request.form.get('specialisation', '').strip()
        role = request.form.get('role', '').strip()

        if request.method=="post":
            if password and password2:
                if password != password2:
                    msg = 'Passwords do not match'
                    return render_template('register_reviewer.html', messages=[msg])

                is_valid, message = validate_password(password)
                if not is_valid:
                    msg = "validation failed"
                    return render_template('register_reviewer.html', messages=[msg])

                try:
                    user.full_name = full_name
                    user.staff_number = staff_number
                    user.email = email
                    user.password = password  # Ensure you hash passwords
                    user.specialisation = specialisation
                    user.role = role

                    db_session.commit()
                    return redirect(url_for('reviewer_list'))

                except Exception as e:
                    db_session.rollback()
                    print("Update error:", str(e))
                    msg = 'Update failed. Please try again.'
                    return render_template('register_reviewer.html', messages=[msg])

            else:
                try:
                    user.full_name = full_name
                    user.staff_number = staff_number
                    user.email = email
                    user.specialisation = specialisation
                    user.role = role

                    db_session.commit()
                    return redirect(url_for('reviewer_list'))

                except Exception as e:
                    db_session.rollback()
                    print("Update error:", str(e))
                    msg = 'Update failed. Please try again.'
                    return render_template('register_reviewer.html', messages=[msg])

    return render_template('edit_user.html',user=user, messages=[msg])

@app.route('/all_users', methods=['GET', 'POST'])
def all_users():
    all_users = db_session.query(User).all()
    return render_template("user-list.html",all_users=all_users)

@app.route('/delete_user/<string:id>', methods=['GET','POST'])
def delete_user(id):
    user = db_session.query(User).filter_by(user_id=id).first()
    msg=''
    if user:
        db_session.delete(user)
        db_session.commit()
        msg="User deleted Successfully"
        return redirect(url_for('chair_landing',messages=[msg]))
    return render_template('register_reviewer.html',user=user)


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
    user.password = new_password
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


@app.route('/ethics_pack', methods=['GET'])
def ethics_pack ():
    user_id = session.get('id') 
    watched_video = db_session.query(Watched).filter_by(user_id=user_id).first()
    if watched_video is None:
        watched_video=Watched(user_id=user_id, watched=True)
        db_session.add(watched_video)
        db_session.commit()
    return render_template('ethics_pack.html')


@app.route('/dashboard', methods=['GET'])
def dashboard ():
    user_id = session.get('id')
    if not user_id:
        return "Unauthorized access. Please log in.", 401
    form_a = db_session.query(FormA).filter_by(user_id=user_id).first()
    date_str=''
    if form_a:
        date=form_a.submitted_at
        date_str = date.strftime('%Y-%m-%d')
  
    return render_template('dashboard.html',date=date_str)

# =====================================================================================================
# THIS SECTION IS FOR HANDLING FORMS
# =====================================================================================================

# FORM A =====================================================================================================


@app.route('/submit_form_a_requirements', methods=['POST'])
def submit_form_a_requirements():

    if request.method=='POST':
        try:
            UPLOAD_FOLDER = 'static/uploads/form'
            
            # Get form data
            needs_permission = request.form.get('need_permission') == 'Yes'
            has_clearance = request.form.get('has_clearance') == 'Yes'
            company_requires_jbs = request.form.get('company_requires_jbs') == 'Yes'

            # Get user ID from session (adjust based on your auth system)
            user_id = session.get('id')
            if not user_id:
                return jsonify({'error': 'Unauthorized'}), 401
            
            # Create uploads directory if it doesn't exist
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            
            # Handle file uploads
            def save_file(file_field_name):
                if file_field_name not in request.files:
                    return None
                file = request.files[file_field_name]
                if file.filename == '':
                    return None
                if file and allowed_file(file.filename):
                    filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)

                    relative_path = os.path.relpath(file_path, start='static')
                   
                    return relative_path.replace("\\", "/")
                return None
            
            # Save files based on form field names (corrected from request.form to request.files)
            permission_letter_path = save_file('permission_letter') if needs_permission else None
            prior_clearance_path = save_file('prior_clearance_path') if has_clearance else None
            research_tools_path = save_file('research_tools_path')
            prior_clearance = save_file('prior_clearance') if company_requires_jbs else None
            prior_clearance1 = save_file('prior_clearance1') if company_requires_jbs else None
            need_jbs_clearance = save_file('need_jbs_clearance') if company_requires_jbs else None
            need_jbs_clearance1 = save_file('need_jbs_clearance1')
            proposal_path = save_file('proposal_path')
            impact_assessment_path = save_file('impact_assessment_path')
            
            # Validate required files
            if not all([research_tools_path, proposal_path, impact_assessment_path]):
                return jsonify({'error': 'Missing required files'}), 400
                
            # Check if form exists for this user
            form = db_session.query(FormARequirements).filter_by(user_id=user_id).first()
         
            if form:
                # Update existing form
                form.needs_permission = needs_permission
                form.has_clearance = has_clearance
                form.company_requires_jbs = company_requires_jbs
                form.prior_clearance1=prior_clearance1
                form.need_jbs_clearance1=need_jbs_clearance1
                form.form_type="FORM A"
                if permission_letter_path:
                    form.permission_letter = permission_letter_path
                if prior_clearance_path:
                    form.prior_clearance = prior_clearance_path
                if research_tools_path:
                    form.research_tools_path = research_tools_path
                if prior_clearance:
                    form.prior_clearance=prior_clearance
                if prior_clearance1:
                    form.prior_clearance1=prior_clearance1
                if need_jbs_clearance:
                    form.need_jbs_clearance=need_jbs_clearance
                if need_jbs_clearance1:
                    form.need_jbs_clearance1=need_jbs_clearance1
                if proposal_path:
                    form.proposal_path = proposal_path
                if impact_assessment_path:
                    form.impact_assessment_path = impact_assessment_path
                
            else:
                # Create new record
                form = FormARequirements(
                    user_id=user_id,
                    form_type="FORM A",
                    needs_permission=needs_permission,
                    permission_letter=permission_letter_path,
                    has_clearance=has_clearance,
                    prior_clearance_path=prior_clearance_path,
                    company_requires_jbs=company_requires_jbs,
                    research_tools_path=research_tools_path,
                    proposal_path=proposal_path,
                    impact_assessment_path=impact_assessment_path,
                    prior_clearance=prior_clearance,
                    prior_clearance1=prior_clearance1,
                    need_jbs_clearance=need_jbs_clearance,
                    need_jbs_clearance1=need_jbs_clearance1
                )
            
            db_session.add(form)
            db_session.commit()
            
            return redirect(url_for('form_a_sec1'))
            
        except Exception as e:
            db_session.rollback()
            return jsonify({'error': str(e)}), 500
        



@app.route('/submit_form_c_requirements', methods=['POST'])
def submit_form_c_requirements():

    if request.method=='POST':
        try:
            UPLOAD_FOLDER = 'static/uploads/form'
            

            # Get user ID from session (adjust based on your auth system)
            user_id = session.get('id')
            if not user_id:
                return jsonify({'error': 'Unauthorized'}), 401
            
            # Create uploads directory if it doesn't exist
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            
            # Handle file uploads
            def save_file(file_field_name):
                if file_field_name not in request.files:
                    return None
                file = request.files[file_field_name]
                if file.filename == '':
                    return None
                if file and allowed_file(file.filename):
                    filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)

                    relative_path = os.path.relpath(file_path, start='static')
                   
                    return relative_path.replace("\\", "/")
                return None
            
            # Save files based on form field names (corrected from request.form to request.files)
            proposal_path = save_file('proposal')

            # Validate required files
            if not all([proposal_path]):
                return jsonify({'error': 'Missing required files'}), 400
                
            # Check if form exists for this user
            form = db_session.query(FormARequirements).filter_by(user_id=user_id).first()
         
            if form:
                # Update existing form
                form.user_id=user_id
                form.form_type="FORM C"
                form.updated_at=datetime.now()
                
                if proposal_path:
                    form.files = proposal_path
                
            else:
                # Create new record
                form = FormARequirements(
                    user_id=user_id,
                    form_type="FORM C",
                    updated_at=datetime.now(),
                    files = proposal_path
                )
            
            db_session.add(form)
            db_session.commit()
            
            return redirect(url_for('form_c_sec1'))
            
        except Exception as e:
            db_session.rollback()
            return jsonify({'error': str(e)}), 500




@app.route('/submit_form_b_requirements', methods=['POST'])
def submit_form_b_requirements():

    if request.method=='POST':
        try:
            UPLOAD_FOLDER = 'static/uploads/form'
            
             # Get form data
            needs_permission = request.form.get('need_permission') == 'Yes'
            has_clearance = request.form.get('has_clearance') == 'Yes'
            has_ethics_evidence=request.form.get('has_ethics_evidence')=='Yes'
            # Get user ID from session (adjust based on your auth system)
            user_id = session.get('id')
            if not user_id:
                return jsonify({'error': 'Unauthorized'}), 401
            
            # Create uploads directory if it doesn't exist
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            
            # Handle file uploads
            def save_file(file_field_name):
                if file_field_name not in request.files:
                    return None
                file = request.files[file_field_name]
                if file.filename == '':
                    return None
                if file and allowed_file(file.filename):
                    filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)

                    relative_path = os.path.relpath(file_path, start='static')
                   
                    return relative_path.replace("\\", "/")
                return None
            
            # Save files based on form field names (corrected from request.form to request.files)
            permission_letter_path = save_file('permission_letter_path') if needs_permission else None
            prior_clearance_path = save_file('prior_clearance_path') if has_clearance else None
            ethics_evidence_path=save_file('ethics_evidence') if has_ethics_evidence else None
            proposal_path = save_file('proposal_path')
            
                
            # Check if form exists for this user
            form = db_session.query(FormARequirements).filter_by(user_id=user_id).first()
         
            if form:
                # Update existing form
                form.needs_permission = needs_permission
                form.has_clearance = has_clearance
                form.has_ethics_evidence=has_ethics_evidence
                form.form_type="FORM B"
                if permission_letter_path:
                    form.permission_letter = permission_letter_path
                if prior_clearance_path:
                    form.prior_clearance_path = prior_clearance_path
                if ethics_evidence_path:
                    form.ethics_evidence = ethics_evidence_path
                if proposal_path:
                    form.proposal_path = proposal_path
              
            else:
                # Create new record
                form = FormARequirements(
                    user_id=user_id,
                    form_type="FORM B",
                    needs_permission=needs_permission,
                    permission_letter=permission_letter_path,
                    has_clearance=has_clearance,
                    prior_clearance_path=prior_clearance_path,
                    has_ethics_evidence=has_ethics_evidence,
                    ethics_evidence=ethics_evidence_path,
                    proposal_path=proposal_path,
                    
                )
            
            db_session.add(form)
            db_session.commit()
            
            return redirect(url_for('form_c_sec1'))
            
        except Exception as e:
            db_session.rollback()
            return jsonify({'error': str(e)}), 500
        


@app.route('/submit_form_a_upload', methods=['GET', 'POST'])
def submit_form_a_upload ():
    try:
        id_list = []
        for field in ['permission_letter', 'prior_clearance', 'need_jbs_clearance', 'research_tools', 'proposal', 'impact_assessment']:
            file = request.files.get(field)
            if file:
                upload = Documents(
                    filename=file.filename,
                    data=file.read(),
                    content_type=file.content_type,
                    field_name=field
                )
                db_session.add(upload)
                db_session.commit()
                id_list.append(upload.id)

        new_file_list = FormUploads(
                    student_id = session['id'],
                    files = json.dumps(id_list),
                    form_type = 'formA',
                )
        db_session.add(new_file_list)
        db_session.commit()      
        session['formA-attachments_id'] = new_file_list.id 
        return jsonify({"message": "Information saved!"}),200
    except:
        return jsonify({"message": "Error, please check all attachments. or check dashboard to continue with form"}),400

@app.route('/edit-form-a/<form_id>', methods=['GET'])
def edit_form_a(form_id):
    data = getFormAData(form_id)
    return render_template('form-a-section1.html', formdata = data)

# ---------------- Section 1 ------------------
@app.route('/form_a_sec1', methods=['GET', 'POST'])
def form_a_sec1 ():
    sup_list = getSupervisorsList()
    if request.method == 'POST':
        # Verify user is logged in
        user_id = session.get('id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401

        # Get form data
        form_data = request.form
        user = db_session.query(User).filter(User.user_id == user_id).first()
        supervisor=db_session.query(User).filter(User.user_id == user.supervisor_id).first()
        form_requirements = db_session.query(FormARequirements).filter(FormARequirements.user_id == user_id).first()
        # Create new record
        form = db_session.query(FormA).filter_by(user_id=user_id).first()
        if form:
            form.user_id=user_id
            form.attachment_id=form_requirements.id
            form.applicant_name=form_data.get('applicant_name')
            form.student_number=form_data.get('student_number')
            form.institution=form_data.get('institution')
            form.department=form_data.get('department')
            form.degree=form_data.get('degree')
            form.study_title=form_data.get('study_title')
            form.mobile=form_data.get('mobile')
            form.email=user.email
            form.supervisor=supervisor.full_name
            form.supervisor_email=supervisor.email
        else:
            form=FormA(
            user_id=user_id,
            attachment_id=form_requirements.id,
            applicant_name=form_data.get('applicant_name'),
            student_number=form_data.get('student_number'),
            institution=form_data.get('institution'),
            department=form_data.get('department'),
            degree=form_data.get('degree'),
            study_title=form_data.get('study_title'),
            mobile=form_data.get('mobile'),
            email=user.email,
            supervisor=supervisor.full_name,
            supervisor_email=supervisor.email,
           )

        db_session.add(form)
        db_session.commit()
        message='form submitted succesffuly'
        return render_template("form-a-section2.html",messages=[message])

    
    return render_template('form-a-section1.html', supervisors=sup_list)
        

   
@app.route('/submit_form_a_sec1', methods=['GET', 'POST'])
def submit_form_a_sec1 ():
    # Dynamically build kwargs from submitted fields matching model attributes
    field_data = {"user_id":session['id'], "attachment_id":session['formA-attachments_id']}
    for key, value in request.form.items():
        if hasattr(FormA, key):
            field_data[key] = value

    formA_record = FormA(**field_data)
    db_session.add(formA_record)
    db_session.commit()
   
    return render_template('form-a-section2.html')

# ---------------- Section 2 ------------------
@app.route('/form_a_sec2', methods=['GET', 'POST'])
def form_a_sec2 ():
    data = request.form
    if request.method == 'POST':
        user_id = session.get('id')

        # Fetch the existing record using user_id
        form = db_session.query(FormA).filter_by(user_id=user_id).first()
        if not form:
            return "No existing Form A record found for this user.", 404
        # 1
        
        if data.get('survey')=='Yes':
            form.survey=True
        else:
            form.survey=False

        if data.get('focus_groups')=='Yes':
            form.focus_groups=True
        else:
            form.focus_groups=False

        if data.get('observations')=='Yes':
            form.observations=True
        else:
            form.observations=False

        if data.get('interviews')=='Yes':
            form.interviews=True
        else:
            form.interviews=False

        if data.get('documents')=='Yes':
            form.documents=True
        else:
            form.documents=False
        
        # section 2.1
        if data.get('vulnerable_communities')=='Yes':
            form.vulnerable_communities=True
        else:
            form.vulnerable_communities=False

        if data.get('age_range')=='Yes':
            form.age_range=True
        else:
            form.age_range=False

        if data.get('uj_employees')=='Yes':
            form.uj_employees=True
        else:
            form.uj_employees=False

        if data.get('vulnerable')=='Yes':
            form.vulnerable=True
        else:
            form.vulnerable=False

        if data.get('non_english')=='Yes':
            form.non_english=True
        else:
            form.non_english=False

        if data.get('own_students')=='Yes':
            form.own_students=True
        else:
            form.own_students=False

        if data.get('poverty')=='Yes':
            form.poverty=True
        else:
            form.poverty=False
        
        if data.get('no_education')=='Yes':
            form.no_education=True
        else:
            form.no_education=False
        
        form.assessment_other_specify==data.get('assessment_other_specify')
        form.vulnerable_other_specify=data.get('vulnerable_other_specify')
        if data.get('vulnerable_comments_1')=='Yes':
            form.vulnerable_comments_1=True
        else:
            form.vulnerable_comments_1=False

        # 2.2
        if data.get('disclosure')=='Yes':
            form.disclosure=True
        else:
            form.disclosure=False

        if data.get('discomfiture')=='Yes':
            form.discomfiture=True
        else:
            form.discomfiture=False

        if data.get('deception')=='Yes':
            form.deception=True
        else:
            form.deception=False
        
        if data.get('sensitive')=='Yes':
            form.sensitive=True
        else:
            form.sensitive=False

        if data.get('prejudice')=='Yes':
            form.prejudice=True
        else:
            form.prejudice=False

        
        if data.get('intrusive_techniques')=='Yes':
            form.intrusive_techniques=True
        else:
            form.intrusive_techniques=False

        if data.get('illegal_activities')=='Yes':
            form.illegal_activities=True
        else:
            form.illegal_activities=False

        if data.get('personal')=='Yes':
            form.personal=True
        else:
            form.personal=False
            
        if data.get('available_records')=='Yes':
            form.available_records=True
        else:
            form.available_records=False

        if data.get('inventories')=='Yes':
            form.inventories=True
        else:
            form.inventories=False

        if data.get('risk_activities')=='Yes':
            form.risk_activities=True
        else:
            form.risk_activities=False

        if data.get('activity_specify')=='Yes':
            form.activity_specify=True
        else:
            form.activity_specify=False
        
        if data.get('vulnerable_comments_2')=='Yes':
            form.vulnerable_comments_2=True
        else:
            form.vulnerable_comments_2=False
        
        # Risk Assessment 2.3
        if data.get('incentives')=='Yes':
            form.incentives=True
        else:
            form.incentives=False

        if data.get('financial_costs')=='Yes':
            form.financial_costs=True
        else:
            form.financial_costs=False

        if data.get('reward')=='Yes':
            form.reward=True
        else:
            form.reward=False
        
        if data.get('conflict')=='Yes':
            form.conflict=True
        else:
            form.conflict=False

        if data.get('uj_premises')=='Yes':
            form.uj_premises=True
        else:
            form.uj_premises=False
  
        if data.get('uj_facilities')=='Yes':
            form.uj_facilities=True
        else:
            form.uj_facilities=False

        if data.get('uj_funding')=='Yes':
            form.uj_funding=True
        else:
            form.uj_funding=False
        
        form.vulnerable_comments_3=data.get('vulnerable_comments_3')
        form.risk_rating = data.get('risk_rating')
        form.risk_justification = data.get('risk_justification')
        form.benefits_description = data.get('benefits_description')
        form.risk_mitigation = data.get('risk_mitigation')
        form.apply_comments=data.get('apply_comments')
        form.interviews_one = data.get('interviews') == 'Yes'
        form.documents_one = data.get('documents') == 'Yes'
        form.other_sec2 = data.get('other_sec2', '')
        
        
        db_session.add(form)
        db_session.commit()
        message= 'Form A sec 2 submitted successfully'
        return render_template("form-a-section3.html",messsages=[message])
    return render_template('form-a-section2.html')

@app.route('/submit_form_a_sec2', methods=['GET', 'POST'])
def submit_form_a_sec2 ():
    form_id = session['formA_id']
    # form = db_session.query(FormA).filter_by(id=form_id).first()
    for key, value in request.form.items():
        print(f'{key}: {value}')

    form_record = db_session.query(FormA).get(form_id)

    # Loop through all form fields and update the model
    # check if type is 
    boolean_fields = {'survey', 'focus_groups', 'observations', 'documents','interviews', 'non_english', 'age_range'}
    # First, handle ALL boolean fields
    for field in boolean_fields:
        if hasattr(form_record, field):
            setattr(form_record, field, field in request.form)

    # Then, handle all text/other fields
    for key, value in request.form.items():
        if hasattr(form_record, key) and key not in boolean_fields:
            setattr(form_record, key, value)


    db_session.commit()
    return render_template('form-a-section3.html')

# ---------------- Section 3 ------------------
@app.route('/form_a_sec3', methods=['GET', 'POST'])
def form_a_sec3 ():
    if request.method == 'POST':
        data = request.form
        user_id = session.get('id')

        if not user_id:
            return "Unauthorized access. Please log in.", 401
        
        form = db_session.query(FormA).filter_by(user_id=user_id).first()
        if not form:
            return "No existing Form A record found for this user.", 404
        

        # Section 3: Project Information
        form.title_provision = data.get('title_provision', '')
        form.abstract = data.get('abstract', '')
        form.questions = data.get('questions', '')
        form.purpose_objectives = data.get('purpose_objectives', '')

        # Section 4: Organisational Permissions and Affiliations
        form.grant_permission=data.get('grant_permission')
        form.org_name = ','.join(data.getlist('org_name[]'))
        form.org_contact = ','.join(data.getlist('org_contact[]'))
        form.org_role = ','.join(data.getlist('org_role[]'))
        form.org_permission = data.get('org_permission')
        
        form.researcher_affiliation = data.get('researcher_affiliation')
        form.affiliation_details = data.get('affiliation_details')

        form.collective_involvement = data.get('collective_involvement')
        form.collective_details = data.get('collective_details')
        # Funding Information
        form.is_funded = data.get('is_funded')
        form.fund_org = ','.join(data.getlist('fund_org[]'))
        form.fund_contact = ','.join(data.getlist('fund_contact[]'))
        form.fund_role = ','.join(data.getlist('fund_role[]'))
        form.fund_amount = ','.join(data.getlist('fund_amount[]'))

        # Indemnity & Other Committee Info
        form.indemnity_arrangements = data.get('indemnity_arrangements')
        form.other_committee = data.get('other_committee')

    

        db_session.add(form)
        db_session.commit()
        message= 'Form submitted successfully'
       
        return render_template("form-a-section4.html",messsages=[message])
    return render_template('form-a-section3.html')


@app.route('/form_a_upload', methods=['GET'])
def form_a_upload ():
    return render_template('form-a-upload.html')

# ---------------- Section 4 ------------------
@app.route('/form_a_sec4', methods=['GET', 'POST'])
def form_a_sec4():
   

    if request.method == 'POST':
        user_id = session.get('id')
        if not user_id:
            return "Unauthorized access. Please log in.", 401

        # Fetch existing form entry for the user
        form = db_session.query(FormA).filter_by(user_id=user_id).first()
        if not form:
            return "No existing Form A record found for this user.", 404

        # 5.1 Research Paradigm
        form.quantitative = 'yes' in request.form.getlist('quantitative[]')
        form.qualitative = 'yes' in request.form.getlist('qualitative[]')
        form.mixed_methods = 'yes' in request.form.getlist('mixed_methods[]')
        form.paradigm_explanation = request.form.get('paradigm_explanation')

        # 5.2 Research Design
        form.design = request.form.get('design')

        # 5.3 Participant Details
        form.participants_description = request.form.get('participants_description')
        form.population = ','.join(request.form.getlist('population[]'))
        form.sampling_method = ','.join(request.form.getlist('sampling_method[]'))
        form.sampling_size = ','.join(request.form.getlist('sample_size[]'))
        form.inclusion_criteria =','.join(request.form.getlist('inclusion_criteria[]'))
        form.duration_timing = request.form.get('duration_timing')
        form.contact_details_method = request.form.get('contact_details_method')
        form.conflict_interest = request.form.get('conflict_interest')=='yes'
        form.conflict_explanation = request.form.get('conflict_explanation')

        # 5.4 Instruments
        form.questionnaire_type = request.form.get('questionnaire_type')
        form.permission_obtained = 'permission_obtained' in request.form
        form.open_source= 'open_source' in request.form
        form.instrument_attachment_reason = request.form.get('instrument_attachment_reason')
        form.data_collection_procedure = request.form.get('data_collection_procedure')
        form.interview_type = request.form.getlist('interview_type')
        form.interview_recording = ','.join(request.form.getlist('interview_recording'))
        form.use_focus_groups = request.form.get('use_focus_groups')=='Yes'
        form.focus_recording = ','.join(request.form.getlist('focus_recording'))
        form.data_collectors = request.form.get('data_collectors')
        form.in_depth=request.form.get("in_depth")
        form.semi_structured=request.form.get("semi_structured")
        form.unstructured=request.form.get("unstructured")
        form.intervention = request.form.get('intervention')=='Yes'
        form.intervention_details = request.form.get('intervention_details')
        form.sensitive_data = request.form.get('sensitive_data')
        form.translator = request.form.get('translator')=='Yes'
        form.translator_procedure = request.form.get('translator_procedure')

        # 5.5 Secondary Data Usage
        secondary_data = request.form.get('secondary_data')  # This should be added as a hidden input for access
        
        if secondary_data == 'Yes':
            form.uses_secondary_data = True
            form.secondary_data_type = request.form.get('data_type')
            if form.secondary_data_type == 'private':
                form.private_permission = request.form.get('privatePermission') == 'Yes'
                # Handle file upload for permission if required
                # Add logic for saving file securely if uploaded
            elif form.secondary_data_type == 'public':
                form.public_data_description = request.form.get('public_data_description')
            else:
                form.secondary_data_type=='both'
        else:
            form.uses_secondary_data = False
        
        # Handle file upload
        file = request.files.get('private_permission')
        if file and file.filename:
            upload_folder = app.config.get('UPLOAD_FOLDER', 'static/uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filename = secure_filename(file.filename)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            form.private_permission_file = filename

        # Save changes to DB
        db_session.commit()

        message = 'Form submitted successfully'
        return render_template('form-a-section5.html', messages=[message])

    return render_template('form-a-section4.html')

@app.route('/submit_form_a_sec4', methods=['GET', 'POST'])
def submit_form_a_sec4 ():
    return render_template('form-a-section5.html')

# ---------------- Section 5 ------------------
@app.route('/form_a_sec5', methods=['GET', 'POST'])
def form_a_sec5 ():
    if request.method == 'POST':
        user_id = session.get('id')
        print("User ID from session:", user_id)

        if not user_id:
            return "Unauthorized access. Please log in.", 401

        # Fetch existing form entry for the user
        form = db_session.query(FormA).filter_by(user_id=user_id).first()
        if not form:
            return "No existing Form A record found for this user.", 404
        
        
        
        form.informed_consent=request.form.get('informed_consent')
        form.secure_location=request.form.getlist('secure_location')
        form.password_protected=request.form.getlist('password_protected')
        form.protected_place=request.form.getlist('protected_place')
        form.retention=request.form.getlist('retention')
        form.study_benefits=request.form.get('study_benefits')
        form.participant_risks=request.form.get('participant_risks')
        form.adverse_steps=request.form.get('adverse_steps')
        form.community_participation=request.form.get('community_participation')
        form.community_effects=request.form.get('community_effects')
        form.remove_identifiers=request.form.getlist("remove_identifiers")
        form.encryption=request.form.getlist("encryption")
        form.pseudonyms=request.form.getlist("pseudonyms")
        form.focus_group_warning=request.form.getlist("focus_group_warning")
        form.privacy=request.form.getlist('privacy[]')
        form.q6_9a= request.form.get("q6_9a")=='yes'
        form.q6_9b=request.form.get("q6_9b")=='yes'
        form.q6_9c=request.form.get("q6_9c")=='yes'
        form.q6_9d=request.form.get("q6_9d")=='yes'
        form.q6_9e=request.form.get("q6_9e")=='yes'
        form.q6_9f=request.form.get("q6_9f")=='yes'
        form.q6_9g=request.form.get("q6_9g")=='yes'
        form.q6_9i=request.form.get("q6_9i")=='yes'
        form.q6_9j=request.form.get("q6_9j")=='yes'
        form.q6_9k=request.form.get("q6_9k")=='yes'
        form.q6_9i=request.form.get("q6_9i")=='yes'
        form.q6_9j=request.form.get("q6_9j")=='yes'
        form.q6_9k=request.form.get("q6_9k")=='yes'
        form.q6_9l=request.form.get("q6_9l")=='yes'
        form.q6_9m=request.form.get("q6_9m")=='yes'
        form.q6_9n=request.form.get("q6_9n")=='yes'
        form.q6_9o=request.form.get("q6_9o")=='yes'
        form.q6_9p=request.form.get("q6_9p")=='yes'
        form.q6_9q=request.form.get("q6_9q")=='yes'
        form.q6_9r=request.form.get("q6_9r")=='yes'
        form.q6_9s=request.form.get("q6_9s")=='yes'
        form.results_feedback=request.form.get('results_feedback')
        form.products_access=request.form.get('products_access')
        form.publication_plans=request.form.get('publication_plans')
        form.participant_comp=request.form.get('participant_comp')
        form.participant_costs=request.form.get('participant_costs')
        form.ethics_reporting=request.form.get('ethics_reporting')
    
        db_session.add(form)
        db_session.commit()
        return render_template('form-a-section6.html')  # Next section
        

    return render_template('form-a-section5.html')

@app.route('/submit_form_a_sec5', methods=['GET', 'POST'])
def submit_form_a_sec5 ():
    return render_template('form-a-section6.html')

# ---------------- Section 6 ------------------
@app.route('/form_a_sec6', methods=['GET', 'POST'])
def form_a_sec6 ():
    if request.method == 'POST':
        user_id = session.get('id')
        if not user_id:
            return "Unauthorized access. Please log in.", 401

        form = db_session.query(FormA).filter_by(user_id=user_id).first()
        if not form:
            return "No existing Form A record found for this user.", 404

        # Save declaration section
        form.declaration_name = request.form.get('declaration_name')
        form.applicant_signature = request.form.get('applicant_signature')

        # Convert string to date
        date_str = request.form.get('declaration_date')
        try:
            form.declaration_date = datetime.strptime(date_str, '%Y-%m-%d')
        except (ValueError, TypeError):
            return "Invalid date format. Please use YYYY-MM-DD.", 400

        db_session.add(form)
        db_session.commit()
        messages="Form A submitted successfully."
        return redirect(url_for('student_dashboard'))  # or any final confirmation route

    
    return render_template('form-a-section6.html')

@app.route('/submit_form_a_sec6', methods=['GET', 'POST'])
def submit_form_a_sec6 ():
    return render_template('dashboard.html')




# FORM B =====================================================================================================
@app.route('/api/form-b/<form_id>', methods=['GET'])
def get_form_b(form_id):
    form_b = db_session.query(FormB).filter_by(form_id=form_id).first()
    if not form_b:
        return jsonify({"message": "Form not found"}), 404
    return jsonify(form_b.to_dict()), 200




@app.route('/form_b_upload', methods=['GET','POST'])
def form_b_upload():
    UPLOAD_FOLDER = 'static/uploads/form_b'
    user_id = session.get('id')
 
    if not user_id:
        return "Unauthorized", 401
    
    if request.method=='POST':
        form = db_session.query(FormB).filter_by(user_id=user_id).first()
        # Get form data
        need_permission = request.form.get('need_permission')
        has_clearance = request.form.get('has_clearance')
        has_ethics_evidence = request.form.get('has_ethics_evidence')

        # Create upload folder if it doesn't exist
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        def save_file(field_name):
            file = request.files.get(field_name)
            if file and file.filename:
                filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                print(f"Saved file to: {file_path}")
                return file_path  # Save full path or relative path for consistency
            return None

        permission_letter = save_file('permission_letter')
        prior_clearance = save_file('prior_clearance')
        ethics_evidence = save_file('ethics_evidence')
        proposal = save_file('proposal')

        if form:
            form.user_id=user_id
            form.need_permission=need_permission=='Yes'
            form.permission_letter=permission_letter
            form.has_clearance=has_clearance=='Yes'
            form.prior_clearance=prior_clearance
            form.has_ethics_evidence=has_ethics_evidence=='Yes'
            form.ethics_evidence=ethics_evidence
            form.proposal=proposal
        else:
            # Save to database
            form = FormB(
                user_id=user_id,
                need_permission=need_permission=='Yes',
                permission_letter=permission_letter,
                has_clearance=has_clearance=='Yes',
                prior_clearance=prior_clearance,
                has_ethics_evidence=has_ethics_evidence=='Yes',
                ethics_evidence=ethics_evidence,
                proposal=proposal
            )

        db_session.add(form)
        db_session.commit()
        message="form submited succesffuly"
        print("submited")
        return render_template("form-b-section1.html",messages=[message])

    return render_template("form-b-upload.html")


@app.route('/form_b_sec1', methods=['GET','POST'])
def form_b_sec1():
    if request.method == 'POST':
        print("im here ")
        user_id=session.get('id')
        if not user_id:
            return jsonify({'error':'unauthorized'}),401
        
        form_data=request.form
        user = db_session.query(User).filter(User.user_id == user_id).first()
        supervisor=db_session.query(User).filter(User.user_id == user.supervisor_id).first()
        form = db_session.query(FormB).filter_by(user_id=user_id).first()
        if form:
            form.user_id=user_id
            form.applicant_name=form_data.get('applicant_name')
            form.student_number=form_data.get('student_number')
            form.institution=form_data.get('institution')
            form.department=form_data.get('department')
            form.degree=form_data.get('degree')
            form.study_title=form_data.get('study_title')
            form.mobile=form_data.get('mobile')
            form.email=user.email
            form.supervisor=supervisor.full_name
            form.supervisor_email=supervisor.email
        else:
            form=FormB(
                user_id=user_id,
                applicant_name=form_data.get('applicant_name'),
                student_number=form_data.get('student_number'),
                institution=form_data.get('institution'),
                department=form_data.get('department'),
                degree=form_data.get('degree'),
                study_title=form_data.get('study_title'),
                mobile=form_data.get('mobile'),
                email=user.email,
                supervisor=supervisor.full_name,
                supervisor_email=supervisor.email,
            )
        db_session.add(form)
        db_session.commit()
        message='form submitted succesffuly'
        return render_template("form-b-section2.html",messages=[message])
    return render_template('form-b-section1.html')


@app.route('/form_b_sec2', methods=['GET','POST'])
def form_b_sec2():
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    if request.method == 'POST':
        form_data = request.form

        form = db_session.query(FormB).filter_by(user_id=user_id).first()

        if not form:
            form = FormB(user_id=user_id)

        form.project_description = form_data.get('project_description')
        form.data_nature = form_data.get('data_nature')
        form.data_origin = form_data.get('data_origin')

        if form_data.get('data_public')=='Yes':
            form.data_public = True
        else: 
            form.data_public=False

        form.public_evidence = form_data.get('public_evidence')
        form.access_conditions = form_data.get('access_conditions')

        if form_data.get('personal_info')== 'Yes':
            form.personal_info = True
        else:
            form.personal_info=False

        form.data_anonymized = form_data.get('data_anonymized')
        form.anonymization_comment = form_data.get('anonymization_comment')

        if form_data.get('private_permission')=='Yes':
            form.private_permission = True
        else:
            form.private_permission=False

        form.permission_details = form_data.get('permission_details')

        if form_data.get('shortcomings_reported')=="Yes":
            form.shortcomings_reported = True
        else:
            form.shortcomings_reported=False

        form.limitations_reporting = form_data.get('limitations_reporting')

        if form_data.get('methodology_alignment')=="Yes":
            form.methodology_alignment = True
        else:
            form.methodology_alignment=False

        form.data_acknowledgment = form_data.get('data_acknowledgment')
        form.rejected_or_accepted=False
        db_session.add(form)
        db_session.commit()
        message="Section 2 saved successfully."

        return render_template("form-b-section3.html", messages=[message])

    return render_template('form-b-section2.html')

@app.route('/form_b_sec3', methods=['GET','POST'])
def form_b_sec3():
   
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
   
    if request.method == 'POST':
        
        form = db_session.query(FormB).filter_by(user_id=user_id).first()
        if not form:
            form = FormB(user_id=user_id)
          
        form.original_clearance=request.form.get('original_clearance')
        form.participant_permission=request.form.get('participant_permission')
        form.data_safekeeping=request.form.get('data_safekeeping')
        form.risk_level=request.form.get('risk_level')
        form.risk_comments=request.form.get('risk_comments')
        form.declaration_name=request.form.get('declaration_name')
        form.full_name=request.form.get('full_name')
        form.declaration_date=datetime.strptime(request.form.get('declaration_date'), '%Y-%m-%d')
        form.submitted_at=datetime.now()
        form.rejected_or_accepted=False
        db_session.add(form)
        db_session.commit()
        return redirect(url_for('student_dashboard'))
        
    return render_template('form_b_section3.html', messages=[], show_modal=False)


@app.route('/form_c_upload', methods=['GET'])
def form_c_upload ():
    return render_template('form-c-upload.html')

@app.route('/form_c_sec1', methods=['GET','POST'])
def form_c_sec1():
    if request.method=='POST':
        user_id=session.get('id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        user = db_session.query(User).filter(User.user_id == user_id).first()
        supervisor=db_session.query(User).filter(User.user_id == user.supervisor_id).first()
        form = db_session.query(FormC).filter_by(user_id=user_id).first()
        if not form:
                form = FormC(user_id=user_id)
       
        form.applicant_name=request.form.get('applicant_name')
        form.student_number=request.form.get('student_number')
        form.institution=request.form.get('institution')
        form.department=request.form.get('department')
        form.degree=request.form.get('degree')
        form.project_title=request.form.get('project_title')
        form.mobile_number=request.form.get('mobile')
        form.email_address=user.email
        form.supervisor_name=supervisor.full_name
        form.supervisor_email=supervisor.email
        form.rejected_or_accepted=False
        form.supervisor_comments=""
        db_session.add(form)
        db_session.commit()
        message="form submitted succesfully"
        return render_template("form-c-section2.html",messages=[message])

    return render_template("form-c-section1.html")


@app.route('/form_a_supervisor/<string:id>',methods=['GET','POST'])
def form_a_supervisor(id):
    form = db_session.query(FormA).filter_by(form_id=id).first()
    
    return render_template("form_a_supervisor.html",formA=form)
    
@app.route('/form_b_supervisor/<string:id>',methods=['GET','POST'])
def form_b_supervisor(id):
    form = db_session.query(FormB).filter_by(form_id=id).first()

    return render_template("form_b_supervisor.html",formB=form)

@app.route('/form_c_supervisor/<string:id>',methods=['GET','POST'])
def form_c_supervisor(id):
    form = db_session.query(FormC).filter_by(form_id=id).first()

    return render_template("form_c_supervisor.html",formc=form)


@app.route('/reject_or_Accept_form_a/<string:id>',methods=['GET','POST'])
def reject_or_Accept_form_a(id):

    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    forma = db_session.query(FormA).filter_by(form_id=id).first()
    if not forma:
        forma = FormA(form_id=id)
    if request.method=="POST":
        supervisor_date=request.form.get('supervisor_date')
        org_permission_comment=request.form.get('org_permission_comment')
        waiver_comment=request.form.get('waiver_comment')
        form_a_comment=request.form.get('form_comment')
        questions_comment=request.form.get('questions_comment')
        consent_comment=request.form.get('consent_comment')
        proposal_comment=request.form.get('proposal_comment')
        supervisor_feedback=request.form.get('supervisor_feedback')
        recommendation=request.form.get('recommendation')
        supervisor_signature=request.form.get('supervisor_signature')
        signature_date=request.form.get('signature_date')
        if request.form.get('recommendation')=='Ready for submission':
            forma.supervisor_date=supervisor_date
            forma.org_permission_comment=org_permission_comment
            forma.waiver_comment=waiver_comment
            forma.form_a_comment=form_a_comment
            forma.questions_comment=questions_comment
            forma.consent_comment=consent_comment
            forma.proposal_comment=proposal_comment
            forma.supervisor_feedback=supervisor_feedback
            forma.recommendation=recommendation
            forma.supervisor_signature=supervisor_signature
            forma.signature_date=signature_date
            forma.rejected_or_accepted=True
        else:
            forma.supervisor_date=supervisor_date
            forma.org_permission_comment=org_permission_comment
            forma.waiver_comment=waiver_comment
            forma.form_a_comment=form_a_comment
            forma.questions_comment=questions_comment
            forma.consent_comment=consent_comment
            forma.proposal_comment=proposal_comment
            forma.supervisor_feedback=supervisor_feedback
            forma.recommendation=recommendation
            forma.rejected_or_accepted=False

        db_session.add(forma)
        db_session.commit()
    return redirect(url_for('supervisor_dashboard'))


@app.route('/reject_or_Accept_form_b/<string:id>',methods=['GET','POST'])
def reject_or_Accept_form_b(id):
    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    formb = db_session.query(FormB).filter_by(form_id=id).first()
    if not formb:
        formb = FormB(form_id=id)
    if request.method=="POST":
 
        supervisor_date=request.form.get('supervisor_date')
        org_permission_comment=request.form.get('org_permission_comment')
        waiver_comment=request.form.get('waiver_comment')
        form_a_comment=request.form.get('form_comment')
        questions_comment=request.form.get('questions_comment')
        consent_comment=request.form.get('consent_comment')
        proposal_comment=request.form.get('proposal_comment')
        supervisor_feedback=request.form.get('supervisor_feedback')
        recommendation=request.form.get('recommendation')
        supervisor_signature=request.form.get('supervisor_signature')
        signature_date=request.form.get('signature_date')
        if request.form.get('recommendation')=='Ready for submission':
            formb.supervisor_date=supervisor_date
            formb.org_permission_comment=org_permission_comment
            formb.waiver_comment=waiver_comment
            formb.form_a_comment=form_a_comment
            formb.questions_comment=questions_comment
            formb.consent_comment=consent_comment
            formb.proposal_comment=proposal_comment
            formb.supervisor_feedback=supervisor_feedback
            formb.recommendation=recommendation
            formb.supervisor_signature=supervisor_signature
            formb.signature_date=signature_date
            formb.rejected_or_accepted=True
        else:
            formb.supervisor_date=supervisor_date
            formb.org_permission_comment=org_permission_comment
            formb.waiver_comment=waiver_comment
            formb.form_a_comment=form_a_comment
            formb.questions_comment=questions_comment
            formb.consent_comment=consent_comment
            formb.proposal_comment=proposal_comment
            formb.supervisor_feedback=supervisor_feedback
            formb.recommendation=recommendation
            formb.rejected_or_accepted=False

        
        db_session.add(formb)
        db_session.commit()
    return redirect(url_for('supervisor_dashboard'))


@app.route('/reject_or_Accept_form_c/<string:id>',methods=['GET','POST'])
def reject_or_Accept_form_c(id):
    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    formc = db_session.query(FormC).filter_by(form_id=id).first()
    if not formc:
        formc = FormC(form_id=id)
    if request.method=="POST":
        supervisor_date=request.form.get('supervisor_date')
        org_permission_comment=request.form.get('org_permission_comment')
        waiver_comment=request.form.get('waiver_comment')
        form_a_comment=request.form.get('form_a_comment')
        questions_comment=request.form.get('questions_comment')
        consent_comment=request.form.get('consent_comment')
        proposal_comment=request.form.get('proposal_comment')
        supervisor_feedback=request.form.get('supervisor_feedback')
        recommendation=request.form.get('recommendation')
        supervisor_signature=request.form.get('supervisor_signature')
        signature_date=request.form.get('signature_date')
        if request.form.get('recommendation')=='Ready for submission':
            formc.supervisor_date=supervisor_date
            formc.org_permission_comment=org_permission_comment
            formc.waiver_comment=waiver_comment
            formc.form_a_comment=form_a_comment
            formc.questions_comment=questions_comment
            formc.consent_comment=consent_comment
            formc.proposal_comment=proposal_comment
            formc.supervisor_feedback=supervisor_feedback
            formc.recommendation=recommendation
            formc.supervisor_signature=supervisor_signature
            formc.signature_date=signature_date
            formc.rejected_or_accepted=True
        else:
            formc.supervisor_date=supervisor_date
            formc.org_permission_comment=org_permission_comment
            formc.waiver_comment=waiver_comment
            formc.form_a_comment=form_a_comment
            formc.questions_comment=questions_comment
            formc.consent_comment=consent_comment
            formc.proposal_comment=proposal_comment
            formc.supervisor_feedback=supervisor_feedback
            formc.recommendation=recommendation
            formc.rejected_or_accepted=False
    db_session.add(formc)
    db_session.commit()
    return redirect(url_for('supervisor_dashboard'))

@app.route('/form_c_sec2', methods=['GET','POST'])
def form_c_sec2():
    if request.method=="POST":
        user_id=session.get('id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        
        form = db_session.query(FormC).filter_by(user_id=user_id).first()
        vulnerable=request.form.get('vulnerable')=="Yes"
        age_under_18_or_over_65=request.form.get('age_under_18_or_over_65')=="Yes"
        uj_employees=request.form.get('uj_employee')=="Yes"
        non_vulnerable_context=request.form.get('non_vulnerable_context')=="Yes"
        non_english=request.form.get('non_english')=="Yes"
        own_students=request.form.get('own_student')=="Yes"
        poverty=request.form.get('poverty')=="Yes"
        non_education=request.form.get('non_education')=="Yes"
        consent_violation=request.form.get('consent_violation')=="Yes"
        discomfiture=request.form.get('discomfiture')=="Yes"
        deception=request.form.get('deception')=="Yes"
        sensitive_issues=request.form.get('sensitive_issues')=="Yes"
        prejuditial_info=request.form.get('prejuditial_info')=="Yes"
        intrusive=request.form.get('intrusive')=="Yes"
        illegal=request.form.get('illegal')=="Yes"
        direct_social_info=request.form.get('direct_social_info')=="Yes"
        identifiable_records=request.form.get('identifiable_records')=="Yes"
        psychology_tests=request.form.get('psychology_tests')=="Yes"
        researcher_risk=request.form.get('reseacher_risk')=="Yes"
        incentives=request.form.get('incentives')=="Yes"
        participant_costs=request.form.get('participant_costs')=="Yes"
        researcher_interest=request.form.get('researcher_interest')=="Yes"
        conflict_of_interest=request.form.get('conflict_of_interest')=="Yes"
        uj_premises=request.form.get('uj_premises')=="Yes"
        uj_facilities=request.form.get('uj_facilities')=="Yes"
        uj_funding=request.form.get('uj_funding')=="Yes"
        if not form:
            form = FormC(user_id=user_id)
        form.vulnerable=vulnerable
        form.age_under_18_or_over_65=age_under_18_or_over_65
        form.uj_employees=uj_employees
        form.non_vulnerable_context=non_vulnerable_context
        form.non_english=non_english
        form.own_students=own_students
        form.poverty=poverty
        form.no_education=non_education
        form.vulnerable_other_description=request.form.get('vulnerable_other_description')
        form.vulnerable_comments=request.form.get('vulnerable_comments')
        form.consent_violation=consent_violation
        form.discomfiture=discomfiture
        form.deception=deception
        form.sensitive_issues=sensitive_issues
        form.prejudicial_info=prejuditial_info
        form.intrusive=intrusive
        form.illegal=illegal
        form.direct_social_info=direct_social_info
        form.identifiable_records=identifiable_records
        form.psychology_tests=psychology_tests
        form.researcher_risk=researcher_risk
        form.activity_other_description=request.form.get('activity_other_description')
        form.activity_comments=request.form.get('activity_comments')
        form.incentives=incentives
        form.participant_costs=participant_costs
        form.researcher_interest=researcher_interest
        form.conflict_of_interest=conflict_of_interest
        form.uj_premises=uj_premises
        form.uj_facilities=uj_facilities
        form.uj_funding=uj_funding
        form.consideration_comments=request.form.get('consideration_comments')    
        form.risk_level=request.form.get('risk_level')
        form.risk_justification=request.form.get('risk_justification')
        form.risk_benefits=request.form.get('risk_benefits')
        form.risk_mitigation=request.form.get('risk_mitigation')

        db_session.add(form)
        db_session.commit()
        message="form submitted succesfully"
        return render_template("form-c-section3.html",messages=[message])
    return render_template("form-c-section2.html")




@app.route('/form_c_sec3', methods=['GET','POST'])
def form_c_sec3():
    if request.method=="POST":
        user_id=session.get('id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        
        form = db_session.query(FormC).filter_by(user_id=user_id).first()
        if not form:
            form = FormC(user_id=user_id)
        
        form.summary_title=request.form.get('summary_title')
        form.executive_summary=request.form.get('executive_summary')
        form.research_questions=request.form.get('research_questions')
        form.research_purpose=request.form.get('research_purpose')
        form.secondary_data_info=request.form.get('secondary_data_info')
        form.exemption_reason=request.form.get('exemption_reason')
    
        db_session.add(form)
        db_session.commit()
        
        message="form submitted succesfully"
        return render_template("form-c-section4.html",messages=[message])
    return render_template("form-c-section3.html")


@app.route('/form_c_sec4', methods=['GET','POST'])
def form_c_sec4():
    if request.method=="POST":
        user_id=session.get('id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        
        form = db_session.query(FormC).filter_by(user_id=user_id).first()
        if not form:
            form = FormC(user_id=user_id)
        form.declaration_name=request.form.get('declaration_name')
        form.full_name=request.form.get('full_name')
        form.submission_date=datetime.now().strptime(request.form.get('submission_date'), '%Y-%m-%d')
        db_session.add(form)
        db_session.commit()
        message="form submitted succesfully"
        return redirect(url_for('student_dashboard'))
    return render_template("form-c-section4.html")


@app.route('/form_a_answers', methods=['GET','POST'])
def form_a_answers():
    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    form = db_session.query(FormA).filter_by(user_id=user_id).first()

    return render_template("form_a_answers.html",formA=form)


@app.route('/student_edit_forma', methods=['GET','POST'])
def student_edit_forma():
    user_id=session.get('id')
    public_data_description=""
    private_permission_file=""
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    user = db_session.query(User).filter(User.user_id == user_id).first()
    supervisor=db_session.query(User).filter(User.user_id == user.supervisor_id).first()
    form = db_session.query(FormA).filter_by(user_id=user_id).order_by(FormA.submitted_at.desc()).first()
    form_requirements = db_session.query(FormARequirements).filter(FormARequirements.user_id == user_id).first()

    if request.method=="POST":
        if request.form.get('survey')=='Yes':
            survey=True
        else:
            survey=False

        if request.form.get('focus_groups')=='Yes':
            focus_groups=True
        else:
            focus_groups=False

        if request.form.get('observations')=='Yes':
            observations=True
        else:
            observations=False

        if request.form.get('interviews')=='Yes':
            interviews=True
        else:
            interviews=False

        if request.form.get('documents')=='Yes':
            documents=True
        else:
            documents=False
        
        if request.form.get('vulnerable_other_specify')=='Yes':
            vulnerable_other_specify=True
        else:
            vulnerable_other_specify=False

        # section 2.1
        if request.form.get('vulnerable_communities')=='Yes':
            vulnerable_communities=True
        else:
            vulnerable_communities=False

        if request.form.get('age_range')=='Yes':
            age_range=True
        else:
            age_range=False

        if request.form.get('uj_employees')=='Yes':
            uj_employees=True
        else:
            uj_employees=False

        if request.form.get('vulnerable')=='Yes':
            vulnerable=True
        else:
            vulnerable=False

        if request.form.get('non_english')=='Yes':
            non_english=True
        else:
            non_english=False

        if request.form.get('own_students')=='Yes':
            own_students=True
        else:
            own_students=False

        if request.form.get('poverty')=='Yes':
            poverty=True
        else:
            poverty=False
        
        if request.form.get('no_education')=='Yes':
            no_education=True
        else:
            no_education=False
        
        form.assessment_other_specify=request.form.get('assessment_other_specify')

        if request.form.get('vulnerable_comments_1')=='Yes':
            vulnerable_comments_1=True
        else:
            vulnerable_comments_1=False

        # 2.2
        if request.form.get('disclosure')=='Yes':
            disclosure=True
        else:
            disclosure=False

        if request.form.get('discomfiture')=='Yes':
            discomfiture=True
        else:
            discomfiture=False

        if request.form.get('deception')=='Yes':
            deception=True
        else:
            deception=False
        
        if request.form.get('sensitive')=='Yes':
            sensitive=True
        else:
            sensitive=False

        if request.form.get('prejudice')=='Yes':
            prejudice=True
        else:
            prejudice=False

        
        if request.form.get('intrusive_techniques')=='Yes':
            intrusive_techniques=True
        else:
            intrusive_techniques=False

        if request.form.get('illegal_activities')=='Yes':
            illegal_activities=True
        else:
            illegal_activities=False

        if request.form.get('personal')=='Yes':
            personal=True
        else:
            personal=False
            
        if request.form.get('available_records')=='Yes':
            available_records=True
        else:
            available_records=False

        if request.form.get('inventories')=='Yes':
            inventories=True
        else:
            inventories=False

        if request.form.get('risk_activities')=='Yes':
            risk_activities=True
        else:
            risk_activities=False

        if request.form.get('activity_specify')=='Yes':
            activity_specify=True
        else:
            activity_specify=False
        
        if request.form.get('vulnerable_comments_2')=='Yes':
            vulnerable_comments_2=True
        else:
            vulnerable_comments_2=False
        
        # Risk Assessment 2.3
        if request.form.get('incentives')=='Yes':
            incentives=True
        else:
            incentives=False

        if request.form.get('financial_costs')=='Yes':
            financial_costs=True
        else:
            financial_costs=False

        if request.form.get('reward')=='Yes':
            reward=True
        else:
            reward=False
        
        if request.form.get('conflict')=='Yes':
            conflict=True
        else:
            conflict=False

        if request.form.get('uj_premises')=='Yes':
            uj_premises=True
        else:
            uj_premises=False
  
        if request.form.get('uj_facilities')=='Yes':
            uj_facilities=True
        else:
            uj_facilities=False

        if request.form.get('uj_funding')=='Yes':
            uj_funding=True
        else:
            uj_funding=False
        
        form.vulnerable_comments_3=request.form.get('vulnerable_comments_3')
        
        if request.form.get('dataType') == 'public':
                public_data_description = request.form.get('public_data_description')

        if request.form.get('researcher_affiliation')=='Yes':
            researcher_affiliation=True
        else:
            researcher_affiliation=False

        if request.form.get('collective_involvement')=='Yes':
            collective_involvement=True
        else:
            collective_involvement=False
       
        secondary_data = request.form.get('secondary_data')  # This should be added as a hidden input for access
     
        if secondary_data == 'Yes':
            form.uses_secondary_data = True
            form.secondary_data_type = request.form.get('data_type')
            if form.secondary_data_type == 'private':
                form.private_permission = request.form.get('privatePermission') == 'Yes'
                # Handle file upload for permission if required
                # Add logic for saving file securely if uploaded
            elif form.secondary_data_type == 'public':
                form.public_data_description = request.form.get('public_data_description')
            
        else:
            form.uses_secondary_data = False
            
        if request.form.get('translator')=='Yes':
            translator=True
        else:
            translator=False

        if request.form.get('intervention')=='Yes':
            intervention=True
        else:
            intervention=False


        if request.form.get('use_focus_groups')=='Yes':
            use_focus_groups=True

        else:
            use_focus_groups=False


        if request.form.get('conflict_interest')=='Yes':
            conflict_interest=True
        else:
            conflict_interest=False

        


            # Handle file upload
        file = request.files.get('private_permission')
        if file and file.filename:
            upload_folder = app.config.get('UPLOAD_FOLDER', 'static/uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filename = secure_filename(file.filename)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            private_permission_file = filename

        interviews_one = request.form.get('interviews') == 'Yes'
        documents_one = request.form.get('documents') == 'Yes'
        form=FormA(
            user_id=user_id,
            attachment_id=form_requirements.id,
            applicant_name=request.form.get('applicant_name'),
            student_number=request.form.get('student_number'),
            institution=request.form.get('institution'),
            department=request.form.get('department'),
            degree=request.form.get('degree'),
            study_title=request.form.get('study_title'),
            mobile=request.form.get('mobile'),
            email=user.email,
            supervisor=supervisor.full_name,
            supervisor_email=supervisor.email,
            survey=survey,
            observations=observations,
            focus_groups=focus_groups,
            interviews=interviews,
            documents=documents,
            vulnerable_other_specify=vulnerable_other_specify,
            vulnerable_communities=vulnerable_communities,
            age_range=age_range,
            uj_employees=uj_employees,
            vulnerable=vulnerable,
            non_english=non_english,
            own_students=own_students,
            poverty=poverty,
            no_education=no_education,
            assessment_other_specify=request.form.get('assessment_other_specify'),
            vulnerable_comments_1=vulnerable_comments_1,
            disclosure=disclosure,
            discomfiture=discomfiture,
            deception=deception,
            sensitive=sensitive,
            prejudice=prejudice,
            intrusive_techniques=intrusive_techniques,
            illegal_activities=illegal_activities,
            personal=personal,
            available_records=available_records,
            inventories=inventories,
            risk_activities=risk_activities,
            activity_specify=activity_specify,
            vulnerable_comments_2=vulnerable_comments_2,
            incentives=incentives,
            financial_costs=financial_costs,
            reward=reward,
            conflict=conflict,
            uj_premises=uj_premises,
            uj_facilities=uj_facilities,
            uj_funding=uj_funding,
            vulnerable_comments_3=request.form.get('vulnerable_comments_3'),
            risk_rating = request.form.get('risk_rating'),
            risk_justification = request.form.get('risk_justification'),
            benefits_description = request.form.get('benefits_description'),
            risk_mitigation = request.form.get('risk_mitigation'),

            interviews_one = interviews_one,
            documents_one = documents_one,
            other_sec2 = request.form.get('other_sec2'),
             # Section 3: Project Information
            title_provision = request.form.get('title_provision'),
            abstract = request.form.get('abstract'),
            questions = request.form.get('questions'),
            purpose_objectives = request.form.get('purpose_objectives'),

            # Section 4: Organisational Permissions and Affiliations
            grant_permission=request.form.get('grant_permission'),
            org_name = request.form.get('org_name[]'),
            org_contact = request.form.get('org_contact[]'),
            org_role = request.form.get('org_role[]'),
            org_permission = request.form.get('org_permission'),
            
            researcher_affiliation = researcher_affiliation,
            affiliation_details = request.form.get('affiliation_details'),

            collective_involvement = collective_involvement,
            

            collective_details = request.form.get('collective_details'),
            # Funding Information
            is_funded = request.form.get('is_funded'),
            fund_org = request.form.get('fund_org[]'),
            fund_contact = request.form.get('fund_contact[]'),
            fund_role = request.form.get('fund_role[]'),
            fund_amount = request.form.get('fund_amount[]'),

            # Indemnity & Other Committee Info
            indemnity_arrangements = request.form.get('indemnity_arrangements'),
            other_committee = request.form.get('other_committee'),
            # 5.1 Research Paradigm
            quantitative = "Yes" in request.form.getlist('quantitative[]'),
            qualitative ="Yes" in request.form.getlist('qualitative[]'),
            mixed_methods = "Yes" in request.form.getlist('mixed_methods[]'),
            paradigm_explanation = request.form.get('paradigm_explanation'),

            # 5.2 Research Design
            design = request.form.get('design'),

            # 5.3 Participant Details
            participants_description = request.form.get('participants_description'),
            population = request.form.getlist('population[]'),
            sampling_method = request.form.getlist('sampling_method[]'),
            sampling_size = request.form.getlist('sample_size[]'),
            inclusion_criteria = request.form.getlist('inclusion_criteria[]'),
            duration_timing = request.form.get('duration_timing'),
            contact_details_method = request.form.get('contact_details_method'),
            conflict_interest = conflict_interest,
            conflict_explanation = request.form.get('conflict_explanation'),

            # 5.4 Instruments
            questionnaire_type = request.form.get('questionnaire_type'),
            permission_obtained = request.form.get('permission_obtained'),
            open_source= request.form.get('open_source'),
            instrument_attachment_reason = request.form.get('instrument_attachment_reason'),
            data_collection_procedure = request.form.get('data_collection_procedure'),
            interview_type = request.form.getlist('interview_type'),
            interview_recording = request.form.getlist('interview_recording'),
            use_focus_groups = use_focus_groups,
            focus_recording = request.form.getlist('focus_recording'),
            data_collectors = request.form.get('data_collectors'),
            in_depth=request.form.get("in_depth"),
            semi_structured=request.form.get("semi_structured"),
            unstructured=request.form.get("unstructured"),
            intervention =intervention, 
            intervention_details = request.form.get('intervention_details'),
            sensitive_data = request.form.get('sensitive_data'),
            translator = translator,
            translator_procedure = request.form.get('translator_procedure'),

            # 5.5 Secondary Data Usage
            
            private_permission= request.form.get('privatePermission'),
            public_data_description=public_data_description,
            private_permission_file=private_permission_file,
            informed_consent=request.form.get('informed_consent'),
            secure_location=request.form.getlist('secure_location[]'),
            password_protected=request.form.getlist('password_protected[]'),
            protected_place=request.form.getlist('protected_place[]'),
            retention=request.form.getlist('retention[]'),
            data_storage=request.form.getlist('data_storage[]'),
            study_benefits=request.form.get('study_benefits'),
            participant_risks=request.form.get('participant_risks'),
            adverse_steps=request.form.get('adverse_steps'),
            community_participation=request.form.get('community_participation'),
            community_effects=request.form.get('community_effects'),
            remove_identifiers=request.form.getlist("remove_identifiers"),
            encryption=request.form.getlist("encryption"),
            pseudonyms=request.form.getlist("pseudonyms"),
            focus_group_warning=request.form.getlist("focus_group_warning"),
            privacy=request.form.getlist('privacy[]'),
            q6_9a= request.form.get("q6_9a")=='Yes',
            q6_9b=request.form.get("q6_9b")=='Yes',
            q6_9c=request.form.get("q6_9c")=='Yes',
            q6_9d=request.form.get("q6_9d")=='Yes',
            q6_9e=request.form.get("q6_9e")=='Yes',
            q6_9f=request.form.get("q6_9f")=='Yes',
            q6_9g=request.form.get("q6_9g")=='Yes',
            q6_9h=request.form.get("q6_9h")=='Yes',
            q6_9i=request.form.get("q6_9i")=='Yes',
            q6_9j=request.form.get("q6_9j")=='Yes',
            q6_9k=request.form.get("q6_9k")=='Yes',
            q6_9l=request.form.get("q6_9l")=='Yes',
            q6_9m=request.form.get("q6_9m")=='Yes',
            q6_9n=request.form.get("q6_9n")=='Yes',
            q6_9o=request.form.get("q6_9o")=='Yes',
            q6_9p=request.form.get("q6_9p")=='Yes',
            q6_9q=request.form.get("q6_9q")=='Yes',
            q6_9r=request.form.get("q6_9r")=='Yes',
            q6_9s=request.form.get("q6_9s")=='Yes',
            results_feedback=request.form.get('results_feedback'),
            products_access=request.form.get('products_access'),
            publication_plans=request.form.get('publication_plans'),
            participant_comp=request.form.get('participant_comp'),
            participant_costs=request.form.get('participant_costs'),
            ethics_reporting=request.form.get('ethics_reporting'),
            submitted_at=datetime.now(),
            declaration_name = request.form.get('declaration_name'),
            applicant_signature = request.form.get('applicant_signature'),
            declaration_date=datetime.now()
        )
       
        db_session.add(form)
        db_session.commit()
        return redirect(url_for('student_dashboard'))
    return render_template("student_edit_forma.html",formA=form)

@app.route('/student_edit_formb', methods=['GET','POST'])
def student_edit_formb():
    user_id=session.get('id')
    
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    user = db_session.query(User).filter(User.user_id == user_id).first()
    supervisor=db_session.query(User).filter(User.user_id == user.supervisor_id).first()
    form = db_session.query(FormB).filter_by(user_id=user_id).order_by(FormB.submitted_at.desc()).first()
    if request.method=="POST":
        data_public= request.form.get('data_public')=='Yes'
        personal_info=request.form.get('personal_info')== 'Yes'
        private_permission=request.form.get('private_permission')=='Yes'
        shortcomings_reported=request.form.get('shortcomings_reported')=="Yes"
        methodology_alignment=request.form.get('methodology_alignment')=="Yes"
                     
        form=FormB(
                user_id=user_id,
                applicant_name=request.form.get('applicant_name'),
                student_number=request.form.get('student_number'),
                institution=request.form.get('institution'),
                department=request.form.get('department'),
                degree=request.form.get('degree'),
                study_title=request.form.get('study_title'),
                mobile=request.form.get('mobile'),
                email=user.email,
                supervisor=supervisor.full_name,
                supervisor_email=supervisor.email,
                project_description = request.form.get('project_description'),
                data_nature = request.form.get('data_nature'),
                data_origin = request.form.get('data_origin'),
                data_public=data_public,
                personal_info=personal_info,

                public_evidence = request.form.get('public_evidence'),
                access_conditions = request.form.get('access_conditions'),

                private_permission=private_permission,

                data_anonymized = request.form.get('data_anonymized'),
                anonymization_comment = request.form.get('anonymization_comment'),

                shortcomings_reported=shortcomings_reported,
                methodology_alignment=methodology_alignment,

                permission_details = request.form.get('permission_details'),

                

                limitations_reporting = request.form.get('limitations_reporting'),

                
                original_clearance=request.form.get('original_clearance'),
                participant_permission=request.form.get('participant_permission'),
                data_safekeeping=request.form.get('data_safekeeping'),
                risk_level=request.form.get('risk_level'),
                risk_comments=request.form.get('risk_comments'),
                declaration_name=request.form.get('declaration_name'),
                full_name=request.form.get('full_name'),
                declaration_date = datetime.now(),
                submitted_at=datetime.now()

            )
   
      
        db_session.add(form)
        db_session.commit()
        return redirect(url_for('student_dashboard'))
    return render_template("student_edit_formb.html",formB=form)

@app.route('/student_edit_formc', methods=['GET','POST'])
def student_edit_formc():
    user_id=session.get('id')
    
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    user = db_session.query(User).filter(User.user_id == user_id).first()
    supervisor=db_session.query(User).filter(User.user_id == user.supervisor_id).first()
    form = db_session.query(FormC).filter_by(user_id=user_id).first()
    if request.method=="POST":
        
        form=FormC(
            user_id=user_id,
            applicant_name=request.form.get('applicant_name'),
            student_number=request.form.get('student_number'),
            institution=request.form.get('institution'),
            department=request.form.get('department'),
            degree=request.form.get('degree'),
            project_title=request.form.get('project_title'),
            mobile_number=request.form.get('mobile_number'),
            email_address=user.email,
            supervisor_name=supervisor.full_name,
            supervisor_email=supervisor.email,
            vulnerable=True if request.form.get('vulnerable') else False,
            
            age_under_18_or_over_65=True if request.form.get('age_under_18_or_over_65') else False,
            uj_employees=True if request.form.get('uj_employee') else False,

            non_vulnerable_context=True if request.form.get('non_vulnerable_context') else False,
            non_english=True if request.form.get('non_english')else False,
            own_students=True if request.form.get('own_student') else False,

            poverty=True if request.form.get('poverty') else False,
            no_education=True if request.form.get('non_education') else False,
            vulnerable_other_description=True if request.form.get('vulnerable_other_description') else False,
            vulnerable_comments=request.form.get('vulnerable_comments'),

            consent_violation=True if request.form.get('consent_violation') else False,
            discomfiture=True if request.form.get('discomfiture') else False,
            deception=True if request.form.get('deception') else False,
            sensitive_issues=True if request.form.get('sensitive_issues') else False,
            prejudicial_info=True if request.form.get('prejuditial_info') else False,
            intrusive=True if request.form.get('intrusive') else False,
            illegal=True if request.form.get('illegal') else False,
            direct_social_info=True if request.form.get('direct_social_info') else False,
            identifiable_records=True if request.form.get('identifiable_records') else False,
            psychology_tests=True if request.form.get('psychology_tests') else False,
            researcher_risk=True if request.form.get('reseacher_risk') else False,
            activity_other_description=request.form.get('activity_other_description'),

            activity_comments=request.form.get('activity_comments'),

            incentives=True if request.form.get('incentives') else False,
            participant_costs=True if request.form.get('participant_costs') else False,
            researcher_interest=True if request.form.get('researcher_interest') else False,
            conflict_of_interest=True if request.form.get('conflict_of_interest') else False,
            uj_premises=True if request.form.get('uj_premises') else False,
            uj_facilities=True if request.form.get('uj_facilities') else False,
            uj_funding=True if request.form.get('uj_funding') else False,
            consideration_comments=request.form.get('consideration_comments'),
            
            risk_level=request.form.get('risk_level'),
            risk_justification=request.form.get('risk_justification'),
            risk_benefits=request.form.get('risk_benefits'),
            risk_mitigation=request.form.get('risk_mitigation'),

            summary_title=request.form.get('summary_title'),
            executive_summary=request.form.get('executive_summary'),
            research_questions=request.form.get('research_questions'),
            research_purpose=request.form.get('research_purpose'),
            secondary_data_info=request.form.get('secondary_data_info'),
            exemption_reason=request.form.get('exemption_reason'),
            declaration_name=request.form.get('declaration_name'),
            full_name=request.form.get('full_name'),
            submission_date=request.form.get('submission_date'),
        )
        db_session.add(form)
        db_session.commit()
        return redirect(url_for('student_dashboard'))
    return render_template('student_edit_formc.html',formc=form)

@app.route('/form_c_answers', methods=['GET','POST'])
def form_c_answers():
    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    form = db_session.query(FormC).filter_by(user_id=user_id).first()
    return render_template("form_c_answers.html",formc=form)

@app.route('/form_d_answers', methods=['GET','POST'])
def form_d_answers():
    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    form = db_session.query(FormD).filter_by(user_id=user_id).first()
    return render_template("form_d_answers.html",form=form)

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
            project_description=data["project_description"],
            data_nature=data["data_nature"],
            data_origin=data["data_origin"],
            data_public=data["data_public"],
            public_evidence=data["public_evidence"],
            access_conditions=data["access_conditions"],
            personal_info=data["personal_info"],
            data_anonymized=data["data_anonymized"],
            anonymization_comment=data["anonymization_comment"],
            private_permission=data["private_permission"],
            permission_details=data["permission_details"],
            shortcomings_reported=data["shortcomings_reported"],
            limitations_reporting=data["limitations_reporting"],
            methodology_alignment=data["methodology_alignment"],
            data_acknowledgment=data["data_acknowledgment"],
            original_clearance=data["original_clearance"],
            participant_permission=data["participant_permission"],
            data_safekeeping=data["data_safekeeping"],
            risk_level=data["risk_level"],
            risk_comments=data["risk_comments"],
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
            ethical_clearance=data["ethical_clearance"],
            clearance_details=data["clearance_details"],
            participant_consent=data["participant_consent"],
            consent_details=data["consent_details"],
            risk_assessment=data["risk_assessment"],
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



@app.route('/chair_dashboard', methods=['GET','POST'])
def chair_dashboard():
    submitted_form_a = (db_session.query(FormA)
    .filter(FormA.submitted_at != None,FormA.rejected_or_accepted == True)
    .distinct(FormA.user_id)
    .all())
    submitted_form_b = (db_session.query(FormB)
    .filter(FormB.submitted_at != None,FormB.rejected_or_accepted == True)
    .distinct(FormB.user_id)
    .all())
    submitted_form_c = (db_session.query(FormC)
    .filter(FormC.submission_date != None,FormC.rejected_or_accepted == True)
    .distinct(FormC.user_id)
    .all())

    today = date.today()
    return render_template('chair-dashboard.html',today=today,submitted_form_a=submitted_form_a,submitted_form_b=submitted_form_b,submitted_form_c=submitted_form_c)


@app.route('/chair_forma_view<string:id>', methods=['GET'])
def chair_forma_view(id):
    form = db_session.query(FormA).filter_by(user_id=id).order_by(desc(FormA.submitted_at)).all()
    form_name="FORM A"
    today = date.today()
    return render_template("chair-forms-dashboard.html",today=today,form_name=form_name,submitted_form=form)


@app.route('/chair_formb_view<string:id>', methods=['GET'])
def chair_formb_view(id):
    form = db_session.query(FormB).filter_by(user_id=id).order_by(desc(FormB.submitted_at)).all()
    form_name="FORM B"
    today = date.today()
    return render_template("chair-forms-dashboard.html",today=today,form_name=form_name,submitted_form=form)

@app.route('/chair_formc_view<string:id>', methods=['GET'])
def chair_formc_view(id):
    form = db_session.query(FormC).filter_by(user_id=id).order_by(desc(FormC.submission_date)).all()
    form_name="FORM C"
    today = date.today()
    return render_template("chair-forms-dashboard.html",today=today,form_name=form_name,submitted_form=form)


@app.route('/student_view_feedback/<string:id>', methods=['GET'])
def student_view_feedback(id):
    form = None
    for model in [FormA, FormB, FormC]:
        form = db_session.query(model).filter_by(form_id=id).first()
        if form:
            break  # Stop once the form is found

    if form:
        return render_template("student-view-feedback.html", view_form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('dashboard'))


@app.route('/supervisor_view_feedback/<string:id>', methods=['GET'])
def supervisor_view_feedback(id):
    form = None
    for model in [FormA, FormB, FormC]:
        form = db_session.query(model).filter_by(form_id=id).first()
        if form:
            break  # Stop once the form is found

    if form:
        return render_template("supervisor-view-feedback.html", view_form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('supervisor_dashboard'))


@app.route('/ethics_view_feedback/<string:id>', methods=['GET'])
def ethics_view_feedback(id):
    form = None
    for model in [FormA, FormB, FormC]:
        form = db_session.query(model).filter_by(form_id=id).first()
        if form:
            break  # Stop once the form is found

    if form:
        return render_template("ethics-view-feedback.html", view_form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('chair_landing'))


@app.route('/reviewer_list/', methods=['GET'])
def reviewer_list():

    form = db_session.query(User).filter(User.role=="REVIEWER").all()
       

    return render_template("reviewer-list.html", view_form=form)
   

@app.route('/chair_form_view/<string:id>/<string:form_name>', methods=['GET','POST'])
def chair_form_view(id,form_name):

    formReviewers = db_session.query(User).filter_by(role="REVIEWER").all()

    if form_name=="FORM A":
        formA = db_session.query(FormA).filter_by(form_id=id).first()
        
        if request.method=="POST":
         
            review_date=request.form.get('review_date')
            review_org_permission_status=request.form.get('org_permission_status')
            review_org_permission_comments=request.form.get('org_permission_comments')
            review_waiver_status=request.form.get('waiver_status')
            review_waiver_comments=request.form.get('waiver_comments')
            review_form_status=request.form.get('form_status')
            review_form_comments=request.form.get('form_comments')
            review_questions_status=request.form.get('questions_status')
            review_questions_comments=request.form.get('questions_comments')
            review_consent_status=request.form.get('consent_status')
            review_consent_comments=request.form.get('consent_comments')
            review_proposal_status=request.form.get('proposal_status')
            review_proposal_comments=request.form.get('proposal_comments')
            review_additional_comments=request.form.get('additional_comments')
            review_recommendation=request.form.get('recommendation')
            review_supervisor_signature=request.form.get('supervisor_signature')
            review_signature_date=request.form.get('signature_date')
            if request.form.get('recommendation')=='Ready for submission':
                if not formA.review_date and not formA.review_date1:
                    
                    formA.review_date=review_date
                    formA.review_org_permission_status=review_org_permission_status
                    formA.review_org_permission_comments=review_org_permission_comments
                    formA.review_waiver_status=review_waiver_status
                    formA.review_waiver_comments=review_waiver_comments
                    formA.review_form_status=review_form_status
                    formA.review_form_comments=review_form_comments
                    formA.review_questions_status=review_questions_status
                    formA.review_questions_comments=review_questions_comments
                    formA.review_consent_status=review_consent_status
                    formA.review_consent_comments=review_consent_comments
                    formA.review_proposal_status=review_proposal_status
                    formA.review_proposal_comments=review_proposal_comments
                    formA.review_additional_comments=review_additional_comments
                    formA.review_recommendation=review_recommendation
                    formA.review_supervisor_signature=review_supervisor_signature
                    formA.review_signature_date=review_signature_date
                    formA.review_status=True
                else:
                    formA.review_date1=review_date
                    formA.review_org_permission_status1=review_org_permission_status
                    formA.review_org_permission_comments1=review_org_permission_comments
                    formA.review_waiver_status1=review_waiver_status
                    formA.review_waiver_comments1=review_waiver_comments
                    formA.review_form_status1=review_form_status
                    formA.review_form_comments1=review_form_comments
                    formA.review_questions_status1=review_questions_status
                    formA.review_questions_comments1=review_questions_comments
                    formA.review_consent_status1=review_consent_status
                    formA.review_consent_comments1=review_consent_comments
                    formA.review_proposal_status1=review_proposal_status
                    formA.review_proposal_comments1=review_proposal_comments
                    formA.review_additional_comments1=review_additional_comments
                    formA.review_recommendation1=review_recommendation
                    formA.review_supervisor_signature1=review_supervisor_signature
                    formA.review_signature_date1=review_signature_date
                    formA.review_status1=True
                
            else:
                formA.review_date=review_date
                formA.review_org_permission_status=review_org_permission_status
                formA.review_org_permission_comments=review_org_permission_comments
                formA.review_waiver_status=review_waiver_status
                formA.review_waiver_comments=review_waiver_comments
                formA.review_form_status=review_form_status
                formA.review_form_comments=review_form_comments
                formA.review_questions_status=review_questions_status
                formA.review_questions_comments=review_questions_comments
                formA.review_consent_status=review_consent_status
                formA.review_consent_comments=review_consent_comments
                formA.review_proposal_status=review_proposal_status
                formA.review_proposal_comments=review_proposal_comments
                formA.review_additional_comments=review_additional_comments
                formA.review_recommendation=review_recommendation
                formA.review_status=False
                
            db_session.add(formA)
            db_session.commit()
            return redirect(url_for('review_dashboard'))
        return render_template("form_a_ethics.html",formA=formA,formReviewers=formReviewers)
    elif form_name=="FORM B":
        formB = db_session.query(FormB).filter_by(form_id=id).first()
        if request.method=="POST":
            review_date=request.form.get('review_date')
            review_org_permission_status=request.form.get('org_permission_status')
            review_org_permission_comments=request.form.get('org_permission_comments')
            review_waiver_status=request.form.get('waiver_status')
            review_waiver_comments=request.form.get('waiver_comments')
            review_form_status=request.form.get('form_status')
            review_form_comments=request.form.get('form_comments')
            review_questions_status=request.form.get('questions_status')
            review_questions_comments=request.form.get('questions_comments')
            review_consent_status=request.form.get('consent_status')
            review_consent_comments=request.form.get('consent_comments')
            review_proposal_status=request.form.get('proposal_status')
            review_proposal_comments=request.form.get('proposal_comments')
            review_additional_comments=request.form.get('additional_comments')
            review_recommendation=request.form.get('recommendation')
            review_supervisor_signature=request.form.get('supervisor_signature')
            review_signature_date=request.form.get('signature_date')
            if request.form.get('recommendation')=='Ready for submission':
                if not formB.review_date and not formB.review_date1:
                
                    formB.review_date=review_date
                    formB.review_org_permission_status=review_org_permission_status
                    formB.review_org_permission_comments=review_org_permission_comments
                    formB.review_waiver_status=review_waiver_status
                    formB.review_waiver_comments=review_waiver_comments
                    formB.review_form_status=review_form_status
                    formB.review_form_comments=review_form_comments
                    formB.review_questions_status=review_questions_status
                    formB.review_questions_comments=review_questions_comments
                    formB.review_consent_status=review_consent_status
                    formB.review_consent_comments=review_consent_comments
                    formB.review_proposal_status=review_proposal_status
                    formB.review_proposal_comments=review_proposal_comments
                    formB.review_additional_comments=review_additional_comments
                    formB.review_recommendation=review_recommendation
                    formB.review_supervisor_signature=review_supervisor_signature
                    formB.review_signature_date=review_signature_date
                    formB.review_status=True
                else:
                    formB.review_date1=review_date
                    formB.review_org_permission_status1=review_org_permission_status
                    formB.review_org_permission_comments1=review_org_permission_comments
                    formB.review_waiver_status1=review_waiver_status
                    formB.review_waiver_comments1=review_waiver_comments
                    formB.review_form_status1=review_form_status
                    formB.review_form_comments1=review_form_comments
                    formB.review_questions_status1=review_questions_status
                    formB.review_questions_comments1=review_questions_comments
                    formB.review_consent_status1=review_consent_status
                    formB.review_consent_comments1=review_consent_comments
                    formB.review_proposal_status1=review_proposal_status
                    formB.review_proposal_comments1=review_proposal_comments
                    formB.review_additional_comments1=review_additional_comments
                    formB.review_recommendation1=review_recommendation
                    formB.review_supervisor_signature1=review_supervisor_signature
                    formB.review_signature_date1=review_signature_date
                    formB.review_status1=True
            else:
                formB.review_date=review_date
                formB.review_org_permission_status=review_org_permission_status
                formB.review_org_permission_comments=review_org_permission_comments
                formB.review_waiver_status=review_waiver_status
                formB.review_waiver_comments=review_waiver_comments
                formB.review_form_status=review_form_status
                formB.review_form_comments=review_form_comments
                formB.review_questions_status=review_questions_status
                formB.review_questions_comments=review_questions_comments
                formB.review_consent_status=review_consent_status
                formB.review_consent_comments=review_consent_comments
                formB.review_proposal_status=review_proposal_status
                formB.review_proposal_comments=review_proposal_comments
                formB.review_additional_comments=review_additional_comments
                formB.review_recommendation=review_recommendation
                formB.review_status1=False
            db_session.add(formB)
            db_session.commit()
            return redirect(url_for('review_dashboard'))
        return render_template("form_b_ethics.html",formB=formB,formReviewers=formReviewers)
    elif form_name=="FORM C":
        formC = db_session.query(FormC).filter_by(form_id=id).first()
     
        if request.method=="POST":
            
            review_date=request.form.get('review_date')
          
            review_org_permission_status=request.form.get('org_permission_status')
            review_org_permission_comments=request.form.get('org_permission_comments')
            review_waiver_status=request.form.get('waiver_status')
            review_waiver_comments=request.form.get('waiver_comments')
            review_form_status=request.form.get('form_status')
            review_form_comments=request.form.get('form_comments')
            review_questions_status=request.form.get('questions_status')
            review_questions_comments=request.form.get('questions_comments')
            review_consent_status=request.form.get('consent_status')
            review_consent_comments=request.form.get('consent_comments')
            review_proposal_status=request.form.get('proposal_status')
            review_proposal_comments=request.form.get('proposal_comments')
            review_additional_comments=request.form.get('additional_comments')
            review_recommendation=request.form.get('recommendation')
            review_supervisor_signature=request.form.get('supervisor_signature')
            review_signature_date=request.form.get('signature_date')
            if request.form.get('recommendation')=='Ready for submission':
                
                if not formC.review_date and not formC.review_date1:
                
                    formC.review_date=review_date
                    formC.review_org_permission_status=review_org_permission_status
                    formC.review_org_permission_comments=review_org_permission_comments
                    formC.review_waiver_status=review_waiver_status
                    formC.review_waiver_comments=review_waiver_comments
                    formC.review_form_status=review_form_status
                    formC.review_form_comments=review_form_comments
                    formC.review_questions_status=review_questions_status
                    formC.review_questions_comments=review_questions_comments
                    formC.review_consent_status=review_consent_status
                    formC.review_consent_comments=review_consent_comments
                    formC.review_proposal_status=review_proposal_status
                    formC.review_proposal_comments=review_proposal_comments
                    formC.review_additional_comments=review_additional_comments
                    formC.review_recommendation=review_recommendation
                    formC.review_supervisor_signature=review_supervisor_signature
                    formC.review_signature_date=review_signature_date
                    formC.review_status=True
                else:
                    formC.review_date1=review_date
                    formC.review_org_permission_status1=review_org_permission_status
                    formC.review_org_permission_comments1=review_org_permission_comments
                    formC.review_waiver_status1=review_waiver_status
                    formC.review_waiver_comments1=review_waiver_comments
                    formC.review_form_status1=review_form_status
                    formC.review_form_comments1=review_form_comments
                    formC.review_questions_status1=review_questions_status
                    formC.review_questions_comments1=review_questions_comments
                    formC.review_consent_status1=review_consent_status
                    formC.review_consent_comments1=review_consent_comments
                    formC.review_proposal_status1=review_proposal_status
                    formC.review_proposal_comments1=review_proposal_comments
                    formC.review_additional_comments1=review_additional_comments
                    formC.review_recommendation1=review_recommendation
                    formC.review_supervisor_signature1=review_supervisor_signature
                    formC.review_signature_date1=review_signature_date
                    formC.review_status1=True
            else:
                formC.review_date=review_date
                formC.review_org_permission_status=review_org_permission_status
                formC.review_org_permission_comments=review_org_permission_comments
                formC.review_waiver_status=review_waiver_status
                formC.review_waiver_comments=review_waiver_comments
                formC.review_form_status=review_form_status
                formC.review_form_comments=review_form_comments
                formC.review_questions_status=review_questions_status
                formC.review_questions_comments=review_questions_comments
                formC.review_consent_status=review_consent_status
                formC.review_consent_comments=review_consent_comments
                formC.review_proposal_status=review_proposal_status
                formC.review_proposal_comments=review_proposal_comments
                formC.review_additional_comments=review_additional_comments
                formC.review_recommendation=review_recommendation
                formC.review_status1=False
            db_session.add(formC)
            db_session.commit()
            return redirect(url_for('review_dashboard'))
        return render_template("form_c_ethics.html",formc=formC,formReviewers=formReviewers)



@app.route('/ethics_reviewer_committee_form_a', methods=['GET','POST'])
def ethics_reviewer_committee_form_a():
    submitted_form_a = (db_session.query(FormA)
    .filter(FormA.submitted_at != None,FormA.rejected_or_accepted == True)
    .distinct(FormA.user_id)
    .all())
    
    supervisor_formA_req=db_session.query(FormARequirements).filter(FormARequirements.user_id == User.user_id).all()
    today = date.today()
    return render_template('ethics_reviewer_committee.html',today=today,submitted_form_a=submitted_form_a,supervisor_formA_req=supervisor_formA_req)


@app.route('/ethics_reviewer_committee_form_b', methods=['GET','POST'])
def ethics_reviewer_committee_form_b():
   
    
    submitted_form_b = (db_session.query(FormB)
    .filter(FormB.submitted_at != None,FormB.rejected_or_accepted == True)
    .distinct(FormB.user_id)
    .all())
    
    
    supervisor_formA_req=db_session.query(FormARequirements).filter(FormARequirements.user_id == User.user_id).all()
    today = date.today()
    return render_template('ethics_reviewer_committee.html',today=today,submitted_form_b=submitted_form_b,supervisor_formA_req=supervisor_formA_req)


@app.route('/ethics_reviewer_committee_form_c', methods=['GET','POST'])
def ethics_reviewer_committee_form_c():
    
    submitted_form_c = (db_session.query(FormC)
    .filter(FormC.submission_date != None,FormC.rejected_or_accepted == True)
    .distinct(FormC.user_id)
    .all())
    
    supervisor_formA_req=db_session.query(FormARequirements).filter(FormARequirements.user_id == User.user_id).all()
    today = date.today()
    return render_template('ethics_reviewer_committee.html',today=today,submitted_form_c=submitted_form_c,supervisor_formA_req=supervisor_formA_req)



@app.route('/chair_landing',methods=['POST','GET'])
def chair_landing():
    ##form A retrival
    formAs = (db_session.query(FormA)
    .filter(FormA.submitted_at != None,FormA.rejected_or_accepted == True)
    .distinct(FormA.user_id)
    .all())

    forms_by_yearA = defaultdict(lambda: defaultdict(list))  # {2025: {2025-06: [form1, form2]}}

    for form in formAs:
        if form.submitted_at:
            year = form.submitted_at.year
            month = form.submitted_at.strftime("%Y-%m")
            forms_by_yearA[year][month].append(form)

    sorted_yearsA = sorted(forms_by_yearA.keys(), reverse=True)

    ## form B retrival
    formBs = (db_session.query(FormB)
    .filter(FormB.submitted_at != None,FormB.rejected_or_accepted == True)
    .distinct(FormB.user_id)
    .all())

    forms_by_yearB = defaultdict(lambda: defaultdict(list))  # {2025: {2025-06: [form1, form2]}}

    for form in formBs:
        if form.submitted_at:
            year = form.submitted_at.year
            month = form.submitted_at.strftime("%Y-%m")
            forms_by_yearB[year][month].append(form)

    sorted_yearsB = sorted(forms_by_yearB.keys(), reverse=True)

    ## form c retrival
    formCs = (db_session.query(FormC)
    .filter(FormC.submission_date != None,FormC.rejected_or_accepted == True)
    .distinct(FormC.user_id)
    .all())

    forms_by_yearC = defaultdict(lambda: defaultdict(list))  # {2025: {2025-06: [form1, form2]}}

    for form in formCs:
        if form.submission_date:
            year = form.submission_date.year
            month = form.submission_date.strftime("%Y-%m")
            forms_by_yearC[year][month].append(form)

    sorted_yearsC = sorted(forms_by_yearC.keys(), reverse=True)
 
    return render_template("chair-landing-dashboard.html", forms_by_yearA=forms_by_yearA, sorted_yearsA=sorted_yearsA,sorted_yearsB=sorted_yearsB,forms_by_yearB=forms_by_yearB,sorted_yearsC=sorted_yearsC,forms_by_yearC=forms_by_yearC)


@app.route('/review_dashboard', methods=['GET','POST'])
def review_dashboard():
    user_id=session['id']
    submitted_form_a = (db_session.query(FormA)
    .filter(or_(
            FormA.reviewer_name1 == user_id,
            FormA.reviewer_name2 == user_id
        ),FormA.submitted_at != None,FormA.rejected_or_accepted == True,FormA.supervisor_signature!= None)
    .distinct(FormA.user_id)
    .all())
    
    submitted_form_b = (db_session.query(FormB)
    .filter(or_(
            FormB.reviewer_name1 == user_id,
            FormB.reviewer_name2 == user_id
        ),FormB.submitted_at != None,FormB.rejected_or_accepted == True,FormB.supervisor_signature!= None)
    .distinct(FormB.user_id)
    .all())
    submitted_form_c = (db_session.query(FormC)
    .filter(or_(
            FormC.reviewer_name1 == user_id,
            FormC.reviewer_name2 == user_id
        ),FormC.submission_date != None,FormC.rejected_or_accepted == True,FormC.supervisor_signature!= None)
    .distinct(FormC.user_id)
    .all())
    x=(db_session.query(FormC)
    .filter(or_(
            FormC.reviewer_name1 == user_id,
            FormC.reviewer_name2 == user_id
        )).all())
    supervisor_formA_req=db_session.query(FormARequirements).filter(FormARequirements.user_id == User.user_id).all()
    today = date.today()
    return render_template('review-dashboard.html',today=today,submitted_form_a=submitted_form_a,submitted_form_b=submitted_form_b,submitted_form_c=submitted_form_c,supervisor_formA_req=supervisor_formA_req)



@app.route('/reviewer_form_a/<string:id>', methods=['GET'])
def reviewer_form_a(id):
    form = db_session.query(FormA).filter_by(form_id=id).first()
    print(form)
    if form:
        return render_template("review_form_a.html", form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('review_dashboard'))


@app.route('/reviewer_form_b/<string:id>', methods=['GET'])
def reviewer_form_b(id):
   
    form = db_session.query(FormB).filter_by(form_id=id).first()

    if form:
        return render_template("review_form_b.html",form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('review_dashboard'))



@app.route('/reviewer_form_c/<string:id>', methods=['GET'])
def reviewer_form_c(id):
    form = db_session.query(FormC).filter_by(form_id=id).first()
   
    if form:
        return render_template("review_form_c.html", form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('review_dashboard'))
    


@app.route('/rec_dashboard', methods=['GET','POST'])
def rec_dashboard():
    user_id=session['id']
    
    submitted_form_a = (db_session.query(FormA)
    .filter(FormA.rejected_or_accepted == True,FormA.review_signature_date!= None,FormA.risk_rating != 'LOW',FormA.review_status==True,FormA.review_status1==True)
    .distinct(FormA.user_id)
    .all())
    
    submitted_form_b = (db_session.query(FormB)
    .filter(FormB.rejected_or_accepted == True,FormB.review_signature_date!= None,FormB.risk_level != 'LOW',FormB.review_status==True,FormB.review_status1==True)
    .distinct(FormB.user_id)
    .all())
    submitted_form_c = (db_session.query(FormC)
    .filter(FormC.rejected_or_accepted == True,FormC.review_signature_date!= None,FormB.risk_level != 'LOW',FormC.review_status==True,FormC.review_status1==True)
    .distinct(FormC.form_id)
    .all())
    supervisor_formA_req=db_session.query(FormARequirements).filter(FormARequirements.user_id == User.user_id).all()
    today = date.today()
    return render_template('rec-dashboard.html',today=today,submitted_form_a=submitted_form_a,submitted_form_b=submitted_form_b,submitted_form_c=submitted_form_c,supervisor_formA_req=supervisor_formA_req)




@app.route('/rec_form_a/<string:id>', methods=['GET'])
def rec_form_a(id):
    
    form = db_session.query(FormA).filter(FormA.form_id==id).first()

    if form:
        return render_template("rec_form_a.html", form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('rec_dashboard'))


@app.route('/rec_form_b/<string:id>', methods=['GET'])
def rec_form_b(id):
   
    form = db_session.query(FormB).filter(FormB.form_id==id).first()

    if form:
        return render_template("rec_form_b.html",form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('rec_dashboard'))



@app.route('/rec_form_c/<string:id>', methods=['GET'])
def rec_form_c(id):
    form = db_session.query(FormC).filter(FormC.form_id==id).first()
   
    if form:
        return render_template("rec_form_c.html", form=form)
    else:
        # You can pass an error message or just load the dashboard
        return redirect(url_for('rec_dashboard'))
    


@app.route('/rec_response/<string:id>', methods=['GET', 'POST'])
def rec_response(id):
    if request.method == 'POST':
        status = request.form.get('status')
        comments = request.form.get('rec_comments')  # ✅ corrected from 'additional_comments'

        # Loop through models to find the correct form by ID
        for model in [FormA, FormB, FormC]:
            form = db_session.query(model).filter_by(form_id=id).first()
            if form:
            
                form.rec_comments = comments
                form.rec_status = status
                form.rec_date=datetime.now()
                db_session.commit()
                flash("Form updated successfully", "success")
                break
        else:
            flash("Form not found", "danger")

        return redirect(url_for('rec_dashboard'))

    return "Invalid access", 405



def generate_clearance_code(committee_acronym, decision_date=None):
    if decision_date is None:
        decision_date = datetime.today()

    # Format the date as YYYYMMDD
    date_str = decision_date.strftime('%Y%m%d')

    total_count = 0  # Initialize total decision count

    for model in [FormA, FormB, FormC]:
        count = (
            db_session.query(func.count())
            .select_from(model)
            .filter(cast(model.rec_date, Date) == decision_date.date())
            .scalar()
        )
        total_count += count

    # Increment for the new decision
    decision_number = total_count + 1

    # Format the final clearance code
    clearance_code = f"{committee_acronym}{date_str}{decision_number:02d}"
    return clearance_code


@app.route('/certificate/<string:id>', methods=['GET', 'POST'])
def certificate(id):
    code = 'JBSREC'
    certification_code = generate_clearance_code(code)

    certificate_details = None
    for model in [FormA, FormB, FormC]:
        certificate_details = db_session.query(model).filter_by(form_id=id).first()
        if certificate_details:
            certificate_details.certificate_code = certification_code
            certificate_details.certificate_issued = datetime.now()

            if request.method == 'POST':
                certificate_details.certificate_valid_years = int(request.form.get('valid_years'))
                certificate_details.certificate_end_date = request.form.get('end_date')
                certificate_details.certificate_issuer = request.form.get('certificate_issuer')
                certificate_details.certificate_email = request.form.get('email')
                # Overwrite with provided issued date if present
                issued_date = request.form.get('certificate_issued')
                if issued_date:
                    certificate_details.certificate_issued = request.form.get('issued_date')
            
            db_session.add(certificate_details)
            db_session.commit()
            
            break

    if not certificate_details:
        return "No certificate data found.", 404

    return render_template(
        'certificate.html',
        certificate_details=certificate_details,
        certification_code=certificate_details.certificate_code
    )


@app.route('/generate_pdf/<string:id>',methods=['GET','POST'])
def generate_pdf(id):
    
    certificate_details = None
    for model in [FormA, FormB, FormC]:
        certificate_details = db_session.query(model).filter_by(form_id=id).first()
        if certificate_details:
            break
    return render_template(
        'view_certificate.html',
        certificate_details=certificate_details
    )


@app.route('/ethics_reviewer_committee_forms/<string:id>/<string:form_name>', methods=['GET','POST'])
def ethics_reviewer_committee_forms(id,form_name):
  
    if form_name=="FORM A":
        formA = db_session.query(FormA).filter_by(form_id=id).first()
        if request.method=="POST":
            reviewers=request.form.getlist('reviewer_names[]')
           
            formA.reviewer_name1=reviewers[0]
            formA.reviewer_name2=reviewers[1] if reviewers[1] else None
            formA.supervisor_date=request.form.get('review_date')
            formA.supervisor_org_permission_status=request.form.get('review_org_permission_status')
            formA.supervisor_org_permission_comments=request.form.get('review_org_permission_comments')
            formA.supervisor_waiver_status=request.form.get('review_waiver_status')
            formA.supervisor_waiver_comments=request.form.get('review_waiver_comments')
            formA.supervisor_form_status=request.form.get('review_form_status')
            formA.supervisor_form_comments=request.form.get('review_form_comments')
            formA.supervisor_questions_status=request.form.get('review_questions_status')
            formA.supervisor_questions_comments=request.form.get('review_questions_comments')
            formA.supervisor_consent_status=request.form.get('review_consent_status')
            formA.supervisor_consent_comments=request.form.get('review_consent_comments')
            formA.supervisor_proposal_status=request.form.get('review_proposal_status')
            formA.supervisor_proposal_comments=request.form.get('review_proposal_comments')
            formA.supervisor_additional_comments=request.form.get('review_additional_comments')
            formA.supervisor_recommendation=request.form.get('review_recommendation')
            formA.supervisor_supervisor_signature=request.form.get('review_supervisor_signature')
            formA.supervisor_signature_date=request.form.get('review_signature_date')
            if request.form.get('accept')=='Accept':
                
                formA.rejected_or_accepted=True
            else:
              
                formA.rejected_or_accepted=False
            db_session.add(formA)
            db_session.commit()
            return redirect(url_for('chair_landing'))
        return render_template("form_a_ethics.html",formA=formA)
    elif form_name=="FORM B":
        formB = db_session.query(FormB).filter_by(form_id=id).first()
        if request.method=="POST":
            reviewers=request.form.getlist('reviewer_names[]')
            formB.reviewer_name1=reviewers[0]
            formB.reviewer_name2=reviewers[1] if reviewers[1] else None
            formB.supervisor_date=request.form.get('review_date')
            formB.supervisor_org_permission_status=request.form.get('review_org_permission_status')
            formB.supervisor_org_permission_comments=request.form.get('review_org_permission_comments')
            formB.supervisor_waiver_status=request.form.get('review_waiver_status')
            formB.supervisor_waiver_comments=request.form.get('review_waiver_comments')
            formB.supervisor_form_status=request.form.get('review_form_status')
            formB.supervisor_form_comments=request.form.get('review_form_comments')
            formB.supervisor_questions_status=request.form.get('review_questions_status')
            formB.supervisor_questions_comments=request.form.get('review_questions_comments')
            formB.supervisor_consent_status=request.form.get('review_consent_status')
            formB.supervisor_consent_comments=request.form.get('review_consent_comments')
            formB.supervisor_proposal_status=request.form.get('review_proposal_status')
            formB.supervisor_proposal_comments=request.form.get('review_proposal_comments')
            formB.supervisor_additional_comments=request.form.get('review_additional_comments')
            formB.supervisor_recommendation=request.form.get('review_recommendation')
            formB.supervisor_supervisor_signature=request.form.get('review_supervisor_signature')
            formB.supervisor_signature_date=request.form.get('review_signature_date')
            
            if request.form.get('accept')=='Accept':
               
                formB.rejected_or_accepted=True
                
            else:
                
                formB.rejected_or_accepted=False
               
            db_session.add(formB)
            db_session.commit()
            return redirect(url_for('chair_landing'))
        return render_template("form_b_ethics.html",formB=formB)
    elif form_name=="FORM C":
        formC = db_session.query(FormC).filter_by(form_id=id).first()
        if request.method=="POST":
            reviewers=request.form.getlist('reviewer_names[]')
          
            formC.reviewer_name1=reviewers[0]
            formC.reviewer_name2=reviewers[1] if reviewers[1] else None
            formC.supervisor_date=request.form.get('review_date')
            formC.supervisor_org_permission_status=request.form.get('review_org_permission_status')
            formC.supervisor_org_permission_comments=request.form.get('review_org_permission_comments')
            formC.supervisor_waiver_status=request.form.get('review_waiver_status')
            formC.supervisor_waiver_comments=request.form.get('review_waiver_comments')
            formC.supervisor_form_status=request.form.get('review_form_status')
            formC.supervisor_form_comments=request.form.get('review_form_comments')
            formC.supervisor_questions_status=request.form.get('review_questions_status')
            formC.supervisor_questions_comments=request.form.get('review_questions_comments')
            formC.supervisor_consent_status=request.form.get('review_consent_status')
            formC.supervisor_consent_comments=request.form.get('review_consent_comments')
            formC.supervisor_proposal_status=request.form.get('review_proposal_status')
            formC.supervisor_proposal_comments=request.form.get('review_proposal_comments')
            formC.supervisor_additional_comments=request.form.get('review_additional_comments')
            formC.supervisor_recommendation=request.form.get('review_recommendation')
            formC.supervisor_supervisor_signature=request.form.get('review_supervisor_signature')
            formC.supervisor_signature_date=request.form.get('review_signature_date')
            if request.form.get('accept')=='Accept':

                formC.rejected_or_accepted=True
            else:
                
                formC.rejected_or_accepted=False
            db_session.add(formC)
            db_session.commit()
            return redirect(url_for('chair_landing'))
        return render_template("ethics_reviewer_committee_forms.html",formC=formC)



@app.route('/request-reset', methods=['POST'])
def request_reset():
    email = request.form.get('email')
    token = generate_reset_token(email)
    if token:
        reset_link = url_for('reset_password', token=token, _external=True)
        send_email(
            to=email,
            subject="Password Reset",
            body=f"Click here to reset: {reset_link}"
        )
        return "Reset email sent!"
    return "Email not found", 404


@app.route('/supervisor_dashboard', methods=['GET','POST'])
def supervisor_dashboard():
    supervisor_id=session.get('id')
    supervisor_role=session['supervisor_role']
    #supervisor_id="bea65156-03ff-45c8-bd41-9d07f4bc48d2"
    if not supervisor_id:
        return jsonify({'error': 'Unauthorized'}), 401
 
    formA = db_session.query(FormA).all()
    formB = db_session.query(FormB).all()
    formC = db_session.query(FormC).all()
 
    supervisor_formA = db_session.query(FormA).join(User, FormA.user_id == User.user_id).filter(User.supervisor_id == supervisor_id).all()
    supervisor_formB = db_session.query(FormB).join(User, FormB.user_id == User.user_id).filter(User.supervisor_id == supervisor_id).all()
    supervisor_formC = db_session.query(FormC).join(User, FormC.user_id == User.user_id).filter(User.supervisor_id == supervisor_id).all()
   
    # supervisor_formA=db_session.query(FormA).filter(FormA.user_id == users.user_id).all()
    # supervisor_formB=db_session.query(FormB).filter(FormB.user_id == users.user_id).all()
    # supervisor_formC=db_session.query(FormC).filter(FormC.user_id == users.user_id).all()
    supervisor_formA_req=db_session.query(FormARequirements).filter(FormARequirements.user_id == User.user_id).all()
    

    return render_template("supervisor-dashboard.html",supervisor_role=supervisor_role,supervisor_formA_req=supervisor_formA_req,formA=formA,formB=formB,formC=formC,supervisor_formA=supervisor_formA,supervisor_formB=supervisor_formB,supervisor_formC=supervisor_formC)

@app.route('/dean_dashboard', methods=['GET','POST'])
def dean_dashboard():
    role="STUDENT"
    supervisor_formA = db_session.query(FormA).join(User, FormA.user_id == User.user_id).all()
    supervisor_formB = db_session.query(FormB).join(User, FormB.user_id == User.user_id).all()
    supervisor_formC = db_session.query(FormC).join(User, FormC.user_id == User.user_id).all()
    supervisor_formA_req=db_session.query(FormARequirements).filter(FormARequirements.user_id == User.user_id).all()
    students=db_session.query(User).filter(User.role==role).all()
    
    return render_template('dean.html',students=students,supervisor_formA_req=supervisor_formA_req,supervisor_formA=supervisor_formA,supervisor_formB=supervisor_formB,supervisor_formC=supervisor_formC)



@app.route('/supervisor_student', methods=['GET', 'POST'])
def supervisor_student ():
    supervisor_id=session['id']
    supervisor_data = (
    db_session.query(User)
    .options(
        joinedload(User.form_a),
        joinedload(User.form_b),
        joinedload(User.form_c),
        joinedload(User.form_a_requirements)
    )
    .filter(User.role == "STUDENT", User.supervisor_id == supervisor_id)
    .all()
        )


    return render_template('students.html',students=supervisor_data)

def validate_reset_token(token):
    user = User.query.filter_by(reset_token=token).first()
    if user and user.reset_token_expiry > datetime.utcnow():
        return user  # Token is valid
    return None  # Token is invalid/expired


# =====================================================================================================
# END OF FORMS
# =====================================================================================================

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))  
    app.run(host='0.0.0.0', port=port, debug=True)