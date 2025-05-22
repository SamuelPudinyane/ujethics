from flask import Flask,flash, render_template, request, redirect, url_for, session, jsonify
from models import db_session, User, UserRole, UserInfo, FormA, FormB, FormC, FormD, FormUploads, Documents,FormARequirements
from utils.helpers import generate_reset_token, send_email, validate_password
import json
from db_queries import getFormAData, getSupervisorsList
import os
from werkzeug.utils import secure_filename
import secrets
from dotenv import load_dotenv
import uuid
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect



# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app) 
csrf = CSRFProtect(app)
app.secret_key = os.getenv('SECRET_KEY')



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
    return render_template('login.html')

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
                
                if role == 'student':
                    student_info = db_session.query(UserInfo).filter_by(user_id=session['id']).first()
                    
                    if student_info and student_info.watched_demo and student_info.test_score is not None and student_info.test_score >= 80:
                        return render_template('dashboard.html', name = session['name'])
                    else:
                        return render_template('video.html')
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
                return render_template('login.html', messages=[error])
        else:
            error = 'Incorrect email or password'
            return render_template('login.html', messages=[error])

    return render_template('login.html')


# hashed_password = User.hash_password("supervisor")
# new_user = User(
#                 full_name="Dr. Thabo Ndlovu",
#                 email="thabo.ndlovu@uj.ac.za",
#                 password=hashed_password,
#                 student_number="",
#                 supervisor_id="",
#                 role="SUPERVISOR"
#             )

# db_session.add(new_user)
# db_session.commit()

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
        print("Raw inputs:", full_name, student_number, email, password, supervisor_id)
        
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
            hashed_password = User.hash_password(password)
            print("Hashed password:", hashed_password)  # Debug print
            
            # Create new user
            new_user = User(
                full_name=full_name,
                student_number=student_number,
                email=email,
                password=hashed_password,  # Make sure this is the hashed version
                supervisor_id=supervisor_id,
                role=UserRole.STUDENT
            )
            
            db_session.add(new_user)
            db_session.commit()
            
            # Debug: Verify what was stored
            stored_user = db_session.query(User).filter_by(email=email).first()
            print("Stored password:", stored_user.password)  # Should start with $2b$
            
            msg = 'You have successfully registered!'
            return render_template("login.html", messages=[msg])
            
        except Exception as e:
            db_session.rollback()
            print("Registration error:", str(e))
            msg = 'Registration failed. Please try again.'
            return render_template('register.html', messages=[msg], supervisors=supervisors)
    
    msg = 'Please fill out the form completely!'
    return render_template('register.html', messages=[msg], supervisors=supervisors)


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


@app.route('/ethics_pack', methods=['GET'])
def ethics_pack ():
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


@app.route('/api/form-a/requirements', methods=['POST'])
def submit_form_a_requirements():
    try:
        UPLOAD_FOLDER = 'uploads/form_a'
        
        # Get form data
        needs_permission = request.form.get('need_permission') == 'Yes'
        has_prior_clearance = request.form.get('has_clearance') == 'Yes'
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
                return file_path
            return None
        
        # Save files based on form field names (corrected from request.form to request.files)
        permission_letter_path = save_file('permission_letter') if needs_permission else None
        prior_clearance_path = save_file('prior_clearance') if has_prior_clearance else None
        research_tools_path = save_file('research_tools')
        proposal_path = save_file('proposal')
        impact_assessment_path = save_file('impact_assessment')
        
        # Validate required files
        if not all([research_tools_path, proposal_path, impact_assessment_path]):
            return jsonify({'error': 'Missing required files'}), 400
            
        # Check if form exists for this user
        form = db_session.query(FormARequirements).filter_by(user_id=user_id).first()
        print("path ",impact_assessment_path)
        if form:
            # Update existing form
            form.needs_permission = needs_permission
            form.has_prior_clearance = has_prior_clearance
            form.company_requires_jbs = company_requires_jbs
            
            if permission_letter_path:
                form.permission_letter_path = permission_letter_path
            if prior_clearance_path:
                form.prior_clearance_path = prior_clearance_path
            if research_tools_path:
                form.research_tools_path = research_tools_path
            if proposal_path:
                form.proposal_path = proposal_path
            if impact_assessment_path:
                form.impact_assessment_path = impact_assessment_path
        else:
            # Create new record
            form = FormARequirements(
                user_id=user_id,
                needs_permission=needs_permission,
                permission_letter_path=permission_letter_path,
                has_prior_clearance=has_prior_clearance,
                prior_clearance_path=prior_clearance_path,
                company_requires_jbs=company_requires_jbs,
                research_tools_path=research_tools_path,
                proposal_path=proposal_path,
                impact_assessment_path=impact_assessment_path
            )
        
        db_session.add(form)
        db_session.commit()
        
        return jsonify({
            'message': 'Form A requirements submitted successfully',
            'id': str(form.id)
        }), 201
        
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
    session['formA_id'] = formA_record.id
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
        
        if data.get('vulnerable_other_specify')=='Yes':
            form.vulnerable_other_specify=True
        else:
            form.vulnerable_other_specify=False

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
        
        if data.get('assessment_other_specify')=='Yes':
            form.assessment_other_specify=True
        else:
            form.assessment_other_specify=False

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
        
        if data.get('vulnerable_comments_3')=='Yes':
            form.vulnerable_comments_3=True
        else:
            form.vulnerable_comments_3=False

        form.risk_rating = data.get('risk_rating')
        form.risk_justification = data.get('risk_justification')
        form.benefits_description = data.get('benefits_description')
        form.risk_mitigation = data.get('risk_mitigation')

        form.interviews_one = data.get('interviews') == 'Yes'
        form.documents_one = data.get('documents') == 'Yes'
        form.other_sec2 = data.get('other_sec2', '')
        
        
        db_session.add(form)
        db_session.commit()
        message= 'Form A submitted successfully'
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
        form.org_name = data.get('org_name', '')
        form.org_contact = data.get('org_contact', '')
        form.org_role = data.get('org_role', '')
        form.org_permission = data.get('org_permission', '')

        form.researcher_affiliation = data.get('researcher_affiliation', '')
        form.affiliation_details = data.get('affiliation_details', '')

        form.collective_involvement = data.get('collective_involvement', '')
        form.collective_details = data.get('collective_details', '')
        # Funding Information
        form.is_funded = data.get('is_funded', '')
        form.fund_org = data.get('fund_org', '')
        form.fund_contact = data.get('fund_contact', '')
        form.fund_role = data.get('fund_role', '')
        form.fund_amount = data.get('fund_amount', '')

        # Indemnity & Other Committee Info
        form.indemnity_arrangements = data.get('indemnity_arrangements', '')
        form.other_committee = data.get('other_committee', '')

    

        db_session.add(form)
        db_session.commit()
        message= 'Form submitted successfully'
        print("im here")
        return render_template("form-a-section4.html",messsages=[message])
    return render_template('form-a-section3.html')


@app.route('/form_a_upload', methods=['GET'])
def form_a_upload ():
    return render_template('form-a-upload.html')

# ---------------- Section 4 ------------------
@app.route('/form_a_sec4', methods=['GET', 'POST'])
def form_a_sec4():
    print("form 4")

    if request.method == 'POST':
        user_id = session.get('id')
        if not user_id:
            return "Unauthorized access. Please log in.", 401

        # Fetch existing form entry for the user
        form = db_session.query(FormA).filter_by(user_id=user_id).first()
        if not form:
            return "No existing Form A record found for this user.", 404

        # 5.1 Research Paradigm
        form.quantitative = request.form.getlist('quantitative[]')=='yes'
        form.qualitative = request.form.getlist('qualitative[]')=='yes'
        form.mixed_methods = request.form.getlist('mixed_methods[]')=='yes'
        form.paradigm_explanation = request.form.get('paradigm_explanation')

        # 5.2 Research Design
        form.design = request.form.get('design')

        # 5.3 Participant Details
        form.participants_description = request.form.get('participants_description')
        form.population = request.form.getlist('population[]')
        form.sampling_method = request.form.getlist('sampling_method[]')
        form.sample_size = request.form.getlist('sample_size[]')
        form.inclusion_criteria = request.form.getlist('inclusion_criteria[]')
        form.duration_timing = request.form.get('duration_timing')
        form.contact_details_method = request.form.get('contact_details_method')
        form.conflict_interest = request.form.get('conflict_interest')=='yes'
        form.conflict_explanation = request.form.get('conflict_explanation')

        # 5.4 Instruments
        form.questionnaire_type = request.form.get('questionnaire_type')
        form.permission_obtained = request.form('permission_obtained')
        form.open_source= request.form('open_source')
        form.instrument_attachment_reason = request.form.get('instrument_attachment_reason')
        form.data_collection_procedure = request.form.get('data_collection_procedure')
        form.interview_type = request.form.getlist('interview_type')
        form.interview_recording = request.form.getlist('interview_recording')
        form.use_focus_groups = request.form.get('use_focus_groups')=='Yes'
        form.focus_recording = request.form.getlist('focus_recording')
        form.data_collectors = request.form.get('data_collectors')
        form.intervention = request.form.get('intervention')=='Yes'
        form.intervention_details = request.form.get('intervention_details')
        form.sensitive_data = request.form.get('sensitive_data')
        form.translator = request.form.get('translator')
        form.translator_procedure = request.form.get('translator_procedure')

        # 5.5 Secondary Data Usage
        form.uses_secondary_data = request.form.get('secondaryData')=='yes'
        form.secondary_data_type = request.form.get('dataType')
        form.private_permission= request.form.get('privatePermission')

        if request.form.get('dataType') == 'public':
            form.public_data_description = request.form.get('public_data_description')

        # Handle file upload
        file = request.files.get('private_permission')
        if file and file.filename:
            upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
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
        form.data_storage=request.form.getlist('data_storage[]')
        form.study_benefits=request.form.get('study_benefits')
        form.participant_risks=request.form.get('participant_risks')
        form.adverse_steps=request.form.get('adverse_steps')
        form.community_participation=request.form.get('community_participation')
        form.community_effects=request.form.get('community_effects')
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
            form.declaration_date = datetime.strptime(date_str, '%Y-%m-%d').date()
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
    UPLOAD_FOLDER = 'uploads/form_b'
    user_id = session.get('id')
    print("something")
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

        db_session.add(form)
        db_session.commit()
        message="Section 2 saved successfully."

        return render_template("form-b-section3.html", messages=[message])

    return render_template('form-b-section2.html')

@app.route('/form_b_sec3', methods=['GET','POST'])
def form_b_sec3():
    print("im here form 3")
    user_id = session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    print("user logged in ")
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
            
        db_session.add(form)
        db_session.commit()
        return redirect(url_for('student_dashboard'))
        
    return render_template('form_b_section3.html', messages=[], show_modal=False)


@app.route('/form_c_sec1', methods=['GET','POST'])
def form_c_sec1():
    if request.method=='POST':
        user_id=session.get('id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        
        form = db_session.query(FormC).filter_by(user_id=user_id).first()
        if not form:
                form = FormC(user_id=user_id)
       
        form.applicant_name=request.form.get('applicant_name')
        form.student_number=request.form.get('student_number')
        form.institution=request.form.get('institution')
        form.department=request.form.get('department')
        form.degree=request.form.get('degree')
        form.project_title=request.form.get('title')
        form.mobile_number=request.form.get('mobile')
        form.email_address=request.form.get('email')
        form.supervisor_name=request.form.get('supervisor_name')
        form.supervisor_email=request.form.get('supervisor_email')
        
        db_session.add(form)
        db_session.commit()
        message="form submitted succesfully"
        return render_template("form-c-section2.html",messages=[message])

    return render_template("form-c-section1.html")


@app.route('/form_c_sec2', methods=['GET','POST'])
def form_c_sec2():
    if request.method=="POST":
        user_id=session.get('id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        
        form = db_session.query(FormC).filter_by(user_id=user_id).first()
        if not form:
            form = FormC(user_id=user_id)
        form.vulnerable=request.form.get('vulnerable'),
        form.vulnerable_other=request.form.get('vulnerable_other'),
        form.vulnerable_comments=request.form.get('vulnerable_comments'),

        form.activity=request.form.get('activity'),
        form.activity_other=request.form.get('activity_other'),
        form.activity_comments=request.form.get('activity_comments'),

        form.consideration=request.form.get('consideration'),
        form.consideration_comments=request.form.get('consideration_comments'),

        form.risk_level=request.form.get('risk_level'),
        form.justify=request.form.get('justify'),
        form.risk_benefits=request.form.get('risk_benefits'),
        form.risk_mitigation=request.form.get('risk_mitigation'),
        
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
        
        form.project_title=request.form.get('project_title')
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
        form.declaration_name=request.form.get('declaration_name'),
        form.full_name=request.form.get('full_name'),
        form.submission_date=datetime.strptime(request.form.get('submission_date'), '%Y-%m-%d')
        db_session.add(form)
        db_session.commit()
        message="form submitted succesfully"
        return render_template("dashboard.html",messages=[message])
    return render_template("form-c-section4.html")


@app.route('/form_a_answers', methods=['GET','POST'])
def form_a_answers():
    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    form = db_session.query(FormA).filter_by(user_id=user_id).first()
    return render_template("form_a_answers.html",forma=form)

@app.route('/form_b_answers', methods=['GET','POST'])
def form_b_answers():
    user_id=session.get('id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    form = db_session.query(FormB).filter_by(user_id=user_id).first()
    
    return render_template("form_b_answers.html",formb=form)

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