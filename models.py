from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, Enum, DateTime, LargeBinary, func, Text
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, Enum, DateTime, LargeBinary, func, Text
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.dialects.postgresql import JSON, ARRAY
from sqlalchemy.types import PickleType
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql
import enum
import uuid
import bcrypt
import datetime
import os
import json
import json

# mySQL_string = 'mysql+pymysql://root:password@localhost/ethics'
# sqlite_string = "sqlite+pysqlite:///ethics.db"
# updated the path so that the database gets created in backend/ethics.db using absolute path, not relative
# db_path = os.path.join(os.path.dirname(__file__), "ethics.db")
# sqlite_string = f"sqlite+pysqlite:///{db_path}"

connection_string = (
    "mssql+pyodbc://@APB-JBS02-113L\\SQLEXPRESS/ethics?"
    "driver=ODBC+Driver+17+for+SQL+Server&"
    "trusted_connection=yes"
)

engine = create_engine(connection_string, echo=True)

Session = sessionmaker(bind=engine)
db_session = Session()

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

# Create an enum class for roles, makes it easy to change at one place if there be additional roles.
class UserRole(enum.Enum):
    STUDENT = "STUDENT"
    SUPERVISOR = "SUPERVISOR"
    ADMIN = "ADMIN"
    REC = "REC"
    REVIEWER = "REVIEWER"
    DEAN = "DEAN"



class User(Base):
    __tablename__ = "users"
    user_id = Column(String(255), primary_key=True, default=generate_uuid)
    full_name = Column(String, nullable=False)
    student_number = Column(Integer, nullable=True)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    supervisor_id = Column(String(255), nullable=True)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.STUDENT)
    reset_token = Column(String, nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)


    def __init__(self, full_name, student_number, email, password, supervisor_id, role):
        self.full_name = full_name
        self.student_number = student_number
        self.email = email
        self.password = self.hash_password(password)
        self.supervisor_id = supervisor_id
        self.role = UserRole(role) if isinstance(role, str) else role

    @staticmethod
    def hash_password(password: str) -> str:
        # Generate salt and hash in one step (bcrypt handles salt internally)
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, plain_password: str) -> bool:
        try:
            print(f"Stored: {self.password}")
            print(f"Input: {plain_password}")
            # Convert stored hash back to bytes
            stored_hash = self.password.encode('utf-8')
            # Verify the password
            return bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash)
        except Exception as e:
            print(f"Password verification error: {e}")
            return False


    
    def to_dict(self):
        return {
            "user_id": self.user_id,
            "full_name": self.full_name,
            "student_number": self.student_number,
            "email": self.email,
            "supervisor_id": self.supervisor_id,
            "role": self.role.value
        }

    def __repr__(self):
        return f"<User {self.full_name} ({self.email})>"

class UserInfo(Base):
    __tablename__ = "user_information"
    id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255), primary_key=True, nullable=False)  #FK User.user_id
    watched_demo = Column(Boolean, nullable=True)
    test_score = Column(Integer, nullable=True)

    def __repr__(self):
        return f"<UserInfo Watched demo video({self.watched_demo}), test score={self.test_score}%>"

class FormUploads(Base):
    __tablename__ = 'form_uploads'
    id = Column(String(255), primary_key=True, default=generate_uuid)
    student_id = Column(String(255), nullable=False)    #FK User.user_id
    form_type = Column(String, nullable=False)
    files = Column(Text, nullable=True)  # Will store JSON list containing id's of files
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, onupdate=func.now(), server_default=func.now(), nullable=False)

    @property
    def files_list(self):
        return json.loads(self.files) if self.files else []
    
    @files_list.setter
    def files_list(self, value):
        self.files = json.dumps(value)


class Documents(Base):
    __tablename__ = 'documents'
    id = Column(String(255), primary_key=True, default=generate_uuid)
    filename = Column(String(255))
    data = Column(LargeBinary)
    content_type = Column(String(255))
    field_name = Column(String(64))
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, onupdate=func.now(), server_default=func.now(), nullable=False)



# FORMS 
class FormARequirements(Base):
    __tablename__ = "form_a_requirements"
    
    id = Column(String(150), primary_key=True, default=generate_uuid)
    user_id = Column(String(150), nullable=False)  # Link to user who submitted
    needs_permission = Column(Boolean, nullable=False)
    permission_letter_path = Column(String(255), nullable=True)
    has_prior_clearance = Column(Boolean, nullable=False)
    prior_clearance_path = Column(String(255), nullable=True)
    company_requires_jbs = Column(Boolean, nullable=False)
    research_tools_path = Column(String(255), nullable=False)
    proposal_path = Column(String(255), nullable=False)
    impact_assessment_path = Column(String(255), nullable=False)
    submitted_at = Column(DateTime, server_default=func.now(), nullable=False)



class FormA(Base):
    __tablename__ = 'form_a'
    id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255), nullable=False)
    attachment_id = Column(String(255), nullable=False) #id of "form-a-upload", stored in current session
    applicant_name = Column(String(120), nullable=False)
    student_number = Column(String(50), nullable=False)
    institution = Column(String(120), nullable=False)
    department = Column(String(120), nullable=False)
    degree = Column(String(120), nullable=False)
    study_title = Column(String(255), nullable=False)
    mobile = Column(String(30), nullable=False)
    email = Column(String(120), nullable=False)
    supervisor = Column(String(120), nullable=False)
    supervisor_email = Column(String(120), nullable=False)
    #section 2
    survey = Column(Boolean, nullable=True)
    focus_groups = Column(Boolean, nullable=True)
    observations = Column(Boolean, nullable=True)
    documents = Column(Boolean, nullable=True)
    interviews = Column(Boolean, nullable=True)
    age_range = Column(Boolean, nullable=True)
    non_english = Column(Boolean, nullable=True)
    uj_employees = Column(Boolean, nullable=True)
    other_sec2 = Column(String(255), nullable=True)

    # section 3
    title_provision=Column(String(255),nullable=True)
    abstract=Column(String(255),nullable=True)
    questions=Column(String(255),nullable=True)
    purpose_objectives=Column(String(255),nullable=True)
    # section 4
    org_name = Column(String(255),nullable=True)
    org_contact = Column(String(255),nullable=True)
    org_role = Column(String(255),nullable=True)
    org_permission = Column(String(50),nullable=True)

    researcher_affiliation = Column(String(10),nullable=True)
    affiliation_details = Column(Text,nullable=True)

    collective_involvement = Column(String(10),nullable=True)
    collective_details = Column(Text,nullable=True)

    is_funded = Column(String(10),nullable=True)
    fund_org = Column(String(255),nullable=True)
    fund_contact = Column(String(255),nullable=True)
    fund_role = Column(String(255),nullable=True)
    fund_amount = Column(String(50),nullable=True)

    indemnity_arrangements = Column(Text,nullable=True)
    other_committee = Column(Text,nullable=True)
    # section 5
    paradigm = Column(String(100),nullable=True)  # Quantitative, Qualitative, Mixed
    paradigm_explanation = Column(Text,nullable=True)
    design = Column(Text,nullable=True)

    participants_description = Column(Text,nullable=True)
    population = Column(String(255),nullable=True)
    sampling_method = Column(String(255),nullable=True)
    sample_size = Column(Integer,nullable=True)
    inclusion_criteria = Column(Text,nullable=True)
    duration_timing = Column(Text,nullable=True)
    contact_details_method = Column(Text,nullable=True)

    conflict_interest = Column(Boolean,nullable=True)
    conflict_explanation = Column(Text,nullable=True)

    questionnaire_type = Column(String(50),nullable=True)  # Self-designed or Existing
    permission_obtained = Column(Boolean,nullable=True)
    open_source = Column(Boolean,nullable=True)
    instrument_attachment_reason = Column(Text,nullable=True)
    data_collection_procedure = Column(Text,nullable=True)

    interview_type = Column(String(255),nullable=True)  # Comma-separated: In-depth, Semi-structured, etc.
    interview_recording = Column(String(255),nullable=True)  # Comma-separated: Audio, Video
    use_focus_groups = Column(Boolean,nullable=True)
    focus_recording = Column(String(255),nullable=True)  # Comma-separated
    focus_group_questions_path = Column(String(255),nullable=True)

    data_collectors = Column(Text,nullable=True)
    intervention = Column(Boolean,nullable=True)
    intervention_details = Column(Text,nullable=True)

    sensitive_data = Column(Text,nullable=True)
    translator = Column(Boolean,nullable=True)
    translator_procedure = Column(Text,nullable=True)
    secondary_data = Column(Boolean,nullable=True)
    secondary_data_details = Column(Text,nullable=True)
    # section 6
    informed_consent = Column(Text,nullable=True)
    sa.Column('data_storage', sa.Text(), nullable=True)  # Store JSON or comma-separated values
    study_benefits = Column(Text,nullable=True)
    participant_risks = Column(Text,nullable=True)
    adverse_steps = Column(Text,nullable=True)
    community_participation = Column(Text,nullable=True)
    community_effects = Column(Text,nullable=True)
    sa.Column('privacy', sa.Text(), nullable=True)  # Store JSON or comma-separated values


    # Questions 6.9a to 6.9s — stored as a dictionary
    q6_9a = Column(Boolean,nullable=True)
    q6_9b=Column(Boolean,nullable=True)
    q6_9c=Column(Boolean,nullable=True)
    q6_9d=Column(Boolean,nullable=True)
    q6_9e=Column(Boolean,nullable=True)
    q6_9f=Column(Boolean,nullable=True)
    q6_9g=Column(Boolean,nullable=True)
    q6_9h=Column(Boolean,nullable=True)
    q6_9i=Column(Boolean,nullable=True)
    q6_9j=Column(Boolean,nullable=True)
    q6_9k=Column(Boolean,nullable=True)
    q6_9l=Column(Boolean,nullable=True)
    q6_9m=Column(Boolean,nullable=True)
    q6_9n=Column(Boolean,nullable=True)
    q6_9o=Column(Boolean,nullable=True)
    q6_9p=Column(Boolean,nullable=True)
    q6_9q=Column(Boolean,nullable=True)
    q6_9r=Column(Boolean,nullable=True)
    q6_9s=Column(Boolean,nullable=True)
    results_feedback = Column(Text,nullable=True)
    products_access = Column(Text,nullable=True)
    publication_plans = Column(Text,nullable=True)
    participant_comp = Column(Text,nullable=True)
    participant_costs = Column(Text,nullable=True)
    ethics_reporting = Column(Text,nullable=True)

    submitted_at = Column(DateTime,server_default=func.now(),nullable=True)

    declaration_name = Column(String(255), nullable=True)
    applicant_signature = Column(String(255), nullable=True)
    declaration_date = Column(String, nullable=True)
    def __repr__(self):
        return f'<FormA {self.applicant_name} ({self.student_number})>'
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

Base.metadata.create_all(engine)


class FormB(Base):
    __tablename__ = "form_b"
    form_id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255), nullable=False)
    need_permission = Column(Boolean, nullable=True)  # "Yes" or "No"
    permission_letter = Column(String(255), nullable=True)  # file path or filename

    has_clearance = Column(Boolean, nullable=True)  # "Yes" or "No"
    prior_clearance = Column(String(255), nullable=True)

    has_ethics_evidence = Column(Boolean, nullable=True)  # "Yes" or "No"
    ethics_evidence = Column(String(255), nullable=True)

    proposal = Column(String(255), nullable=True)  # Proposal file
    
    # section 1

    applicant_name = Column(String(120), nullable=True)
    student_number = Column(String(50), nullable=True)
    institution = Column(String(120), nullable=True)
    department = Column(String(120), nullable=True)
    degree = Column(String(120), nullable=True)
    study_title = Column(String(255), nullable=True)
    mobile = Column(String(30), nullable=True)
    email = Column(String(120), nullable=True)
    supervisor = Column(String(120), nullable=True)
    supervisor_email = Column(String(120), nullable=True)

    # section 2
    project_description = Column(Text, nullable=True)
    data_nature = Column(String(255), nullable=True)
    data_origin = Column(String(255), nullable=True)
    data_public = Column(Boolean, nullable=True)  # "Yes" or "No"
    public_evidence = Column(Text, nullable=True)
    access_conditions = Column(Text, nullable=True)
    personal_info = Column(Boolean, nullable=True)
    data_anonymized = Column(String(20), nullable=True)  # Yes / No / Not Applicable
    anonymization_comment = Column(Text, nullable=True)
    private_permission = Column(Boolean, nullable=True)  # "Yes" or "No"
    permission_details = Column(Text, nullable=True)
    shortcomings_reported = Column(Boolean, nullable=True)  # "Yes" or "No"
    limitations_reporting = Column(Text, nullable=True)
    methodology_alignment = Column(Boolean, nullable=True)  # "Yes" or "No"
    data_acknowledgment = Column(Text, nullable=True)

    # section 3
    # Ethical Considerations
    original_clearance = Column(String(20), nullable=True)
    participant_permission = Column(String(20), nullable=True)
    data_safekeeping = Column(Text, nullable=True)
    
    # Risk Assessment
    risk_level = Column(String(20), nullable=True)
    risk_comments = Column(Text, nullable=True)
    
    # Declaration
    declaration_name = Column(String(150), nullable=True)
    full_name = Column(String(150), nullable=True)
    declaration_date = Column(DateTime, nullable=True)

    submitted_at = Column(DateTime, server_default=func.now())
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
    

class FormC(Base):
    __tablename__ = "form_c"
    form_id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255), nullable=False)
    applicant_name = Column(String, nullable=True)
    student_number = Column(Integer, nullable=True)
    institution = Column(String, nullable=True)
    department = Column(String, nullable=True)
    degree = Column(String, nullable=True)
    project_title = Column(String, nullable=True)
    mobile_number = Column(String, nullable=True)
    email_address = Column(String(120), nullable=True)
    supervisor_name = Column(String, nullable=True)
    supervisor_email = Column(String, nullable=True)
    # section 2
    # Section 2.1 - Vulnerable groups
    vulnerable = Column(PickleType, nullable=True)  # List of selected checkboxes
    vulnerable_other = Column(Text, nullable=True)
    vulnerable_comments = Column(Text, nullable=True)

    # Section 2.2 - Research activity types
    activity = Column(PickleType, nullable=True)  # List of selected checkboxes
    activity_other = Column(Text, nullable=True)
    activity_comments = Column(Text, nullable=True)

    # Section 2.3 - Additional considerations
    consideration = Column(PickleType, nullable=True)  # List of selected checkboxes
    consideration_comments = Column(Text, nullable=True)

    # Risk level and justification
    risk_level = Column(String(50), nullable=True)
    justify = Column(Text, nullable=True)
    risk_benefits = Column(Text, nullable=True)
    risk_mitigation = Column(Text, nullable=True)

    # section 3
    
    executive_summary = Column(Text,nullable=True)
    research_questions = Column(Text,nullable=True)
    research_purpose = Column(Text,nullable=True)
    secondary_data_info = Column(Text,nullable=True)
    exemption_reason = Column(Text,nullable=True)

    # section 4
    declaration_name = Column(String(255), nullable=True)  # from the embedded paragraph
    full_name = Column(String(255), nullable=True)
    submission_date = Column(DateTime, nullable=True)

    ethical_clearance = Column(Boolean, nullable=True)
    clearance_details = Column(String, nullable=True)
    participant_consent = Column(Boolean, nullable=True)
    consent_details = Column(String, nullable=True)
    risk_assessment = Column(String, nullable=True)
    declaration_full_name = Column(String, nullable=True)
    declaration_date = Column(DateTime, nullable=True)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
    


    # try:
#     users = [
#         User("Prof Albert Einstein", None, "eistein@uj.ac.za", "1234", None, "supervisor"),
#         User("Prof. Lerato Mokoena", None, "lmokoena@uj.ac.za", "1234", None, "dean"),
#         User("Dr. John Naidoo", None, "jnaidoo@uj.ac.za", "1234", None, "rec"),
#         User("Ms. Zanele Dlamini", None, "zdlamini@uj.ac.za", "1234", None, "student"),
#         User("Dr. Fatima Patel", None, "fpatel@uj.ac.za", "1234", None, "reviewer"),
#         User("Prof. Tshidi Mthembu", None, "tmthembu@uj.ac.za", "1234", None, "supervisor"),
#         User("Prof. Samuel van der Merwe", None, "svdmerwe@uj.ac.za", "1234", None, "supervisor"),
#         User("Dr. Bongani Khumalo", None, "bkhumalo@uj.ac.za", "1234", None, "reviewer"),
#         User("Ms. Nomsa Nkosi", None, "nnkosi@uj.ac.za", "1234", None, "reviewer"),
#         User("Prof. Peter Botha", None, "pbotha@uj.ac.za", "1234", None, "supervisor")
#     ]

#     db_session.add_all(users)
#     db_session.commit()
# except Exception as e:
#     print("Failed to store user. \n", e)

    


    # try:
#     users = [
#         User("Prof Albert Einstein", None, "eistein@uj.ac.za", "1234", None, "supervisor"),
#         User("Prof. Lerato Mokoena", None, "lmokoena@uj.ac.za", "1234", None, "dean"),
#         User("Dr. John Naidoo", None, "jnaidoo@uj.ac.za", "1234", None, "rec"),
#         User("Ms. Zanele Dlamini", None, "zdlamini@uj.ac.za", "1234", None, "student"),
#         User("Dr. Fatima Patel", None, "fpatel@uj.ac.za", "1234", None, "reviewer"),
#         User("Prof. Tshidi Mthembu", None, "tmthembu@uj.ac.za", "1234", None, "supervisor"),
#         User("Prof. Samuel van der Merwe", None, "svdmerwe@uj.ac.za", "1234", None, "supervisor"),
#         User("Dr. Bongani Khumalo", None, "bkhumalo@uj.ac.za", "1234", None, "reviewer"),
#         User("Ms. Nomsa Nkosi", None, "nnkosi@uj.ac.za", "1234", None, "reviewer"),
#         User("Prof. Peter Botha", None, "pbotha@uj.ac.za", "1234", None, "supervisor")
#     ]

#     db_session.add_all(users)
#     db_session.commit()
# except Exception as e:
#     print("Failed to store user. \n", e)
