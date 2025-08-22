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
from datetime import datetime 

import os
import json
import time
from sqlalchemy.exc import OperationalError
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate


# mySQL_string = 'mysql+pymysql://root:password@localhost/ethics'
# sqlite_string = "sqlite+pysqlite:///ethics.db"
# updated the path so that the database gets created in backend/ethics.db using absolute path, not relative
# db_path = os.path.join(os.path.dirname(__file__), "ethics.db")
# sqlite_string = f"sqlite+pysqlite:///{db_path}"

# DB_SERVER = os.getenv("DB_SERVER", "sqlserver")
# DB_PORT = os.getenv("DB_PORT", "1433")
# DB_NAME = os.getenv("DB_NAME", "ethics")
# DB_USER = os.getenv("DB_USER", "sa")
# DB_PASSWORD = os.getenv("DB_PASSWORD", "malvapudding78*")

DB_SERVER = os.getenv("DB_SERVER", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "ethics")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "malvapudding78*")

# DB_SERVER = os.getenv("DB_SERVER", "localhost")
# DB_PORT = os.getenv("DB_PORT", "5432")
# DB_NAME = os.getenv("DB_NAME", "ethics")
# DB_USER = os.getenv("DB_USER", "postgres")
# DB_PASSWORD = os.getenv("DB_PASSWORD", "Musa")


connection_string = (
    f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_SERVER}:{DB_PORT}/{DB_NAME}"
)




# connection_string = (
#     "mssql+pyodbc://@APB-JBS02-113L\\SQLEXPRESS/ethics?"
#     "driver=ODBC+Driver+17+for+SQL+Server&"
#     "trusted_connection=yes"
# )

# connection_string = (
#     "mssql+pyodbc://@MOOSE\\SQLEXPRESS/ethics?"
#     "driver=ODBC+Driver+17+for+SQL+Server&"
#     "trusted_connection=yes"
# )

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
    ADMIN = "ADMIN" ##ethics
    REC = "REC" #rec commette final 
    REVIEWER = "REVIEWER" #ethics sent the form to reviwer, review send it to rec only if its high risk and medium
    DEAN = "DEAN" ##chairman, no responsibility
    SUPER_ADMIN="SUPER_ADMIN"



class User(Base):
    __tablename__ = "users"
    user_id = Column(String(255), primary_key=True, default=generate_uuid)
    full_name = Column(String, nullable=False)
    student_number = Column(Integer, nullable=True)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    supervisor_id = Column(String(255), nullable=True)
    staff_number=Column(String(255),nullable=True)
    specialisation=Column(String(255),nullable=True)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.STUDENT)
    reset_token = Column(String, nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)
    authenticate_student=Column(String,default=False)
    form_a = relationship("FormA", backref="user", lazy=True)
    form_b = relationship("FormB", backref="user", lazy=True)
    form_c = relationship("FormC", backref="user", lazy=True)
    form_a_requirements = relationship("FormARequirements", backref="user", lazy=True)

    def __init__(self, full_name, student_number=None, email=None,staff_number=None,specialisation=None, password=None, supervisor_id=None, role=None):
        self.full_name = full_name
        self.student_number = student_number
        self.email = email
        self.staff_number=staff_number
        self.password = self.hash_password(password)
        self.supervisor_id = supervisor_id
        self.specialisation=specialisation
        self.role = UserRole(role) if isinstance(role, str) else role
      
    @staticmethod
    def hash_password(password: str) -> str:
        # Generate salt and hash in one step (bcrypt handles salt internally)
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, plain_password: str) -> bool:
        try:
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
            "staff_number":self.staff_number,
            "specialisation":self.specialisation,
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
    user_id = Column(String(255),ForeignKey("users.user_id"), nullable=True)  # Link to user who submitted
    form_a = relationship(
        "FormA",
        primaryjoin="FormA.user_id == foreign(FormARequirements.user_id)",
        back_populates="form_a_requirements"
    )
    form_b = relationship(
        "FormB",
        primaryjoin="FormB.user_id == foreign(FormARequirements.user_id)",
        back_populates="form_a_requirements"
    )
    form_c = relationship(
        "FormC",
        primaryjoin="FormC.user_id == foreign(FormARequirements.user_id)",
        back_populates="form_a_requirements"
    )
    form_type = Column(String, nullable=False)
    needs_permission = Column(Boolean,default=False, nullable=True)
    permission_letter = Column(String(255), nullable=True)
    has_clearance = Column(Boolean,default=False, nullable=True)
    prior_clearance_path = Column(String(255), nullable=True)
    company_requires_jbs = Column(Boolean,default=False, nullable=True)
    prior_clearance = Column(String(255), nullable=True)
    need_jbs_clearance1 = Column(String(255), nullable=True)
    need_jbs_clearance=Column(String(255),nullable=True)
    prior_clearance1=Column(String(255),nullable=True)
    research_tools_path = Column(String(255), nullable=True)
    proposal_path = Column(String(255), nullable=True)
    impact_assessment_path = Column(String(255), nullable=True)
    has_ethics_evidence=Column(Boolean,default=False,nullable=True)
    participation_info_sheet=Column(String(255),nullable=True)
    ethics_evidence = Column(Boolean, default=False, nullable=True)
    ethics_evidence_path=Column(String,nullable=True)
    files = Column(Text, nullable=True)  # Will store JSON list containing id's of files
    submitted_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), nullable=False)
    

class FormA(Base):
    __tablename__ = 'form_a'
    form_id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255),ForeignKey("users.user_id"), nullable=False)
    form_a_requirements = relationship(
        "FormARequirements",
        primaryjoin="FormA.user_id == foreign(FormARequirements.user_id)",
        back_populates="form_a",
        uselist=False  # Assuming one requirements record per FormA/user
    )
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
    # 1
    survey = Column(Boolean, nullable=True)
    focus_groups = Column(Boolean, nullable=True)
    observations = Column(Boolean, nullable=True)
    interviews = Column(Boolean, nullable=True)
    documents = Column(Boolean, nullable=True)
    vulnerable_other_specify = Column(String(255), nullable=True)
    # 2.1
    vulnerable_communities=Column(Boolean,nullable=True)
    age_range = Column(Boolean, nullable=True)
    uj_employees = Column(Boolean, nullable=True)
    vulnerable=Column(Boolean,nullable=True)
    non_english = Column(Boolean, nullable=True)
    own_students=Column(Boolean,nullable=True)
    poverty = Column(Boolean,nullable=True)
    no_education = Column(Boolean,nullable=True)
    assessment_other_specify = Column(String(255),nullable=True)
    vulnerable_comments_1 = Column(Text,nullable=True)

    # Risk Assessment 2.2
    disclosure = Column(Boolean,nullable=True)
    discomfiture = Column(Boolean,nullable=True)
    deception = Column(Boolean,nullable=True)
    sensitive = Column(Boolean,nullable=True)
    prejudice = Column(Boolean,nullable=True)
    intrusive_techniques = Column(Boolean,nullable=True)
    illegal_activities = Column(Boolean,nullable=True)
    personal = Column(Boolean,nullable=True)
    available_records = Column(Boolean,nullable=True)
    inventories = Column(Boolean,nullable=True)
    risk_activities = Column(Boolean,nullable=True)
    activity_specify = Column(String(255),nullable=True)
    vulnerable_comments_2 = Column(Text,nullable=True)

    # Risk Assessment 2.3
    incentives = Column(Boolean,nullable=True)
    financial_costs = Column(Boolean,nullable=True)
    reward = Column(Boolean,nullable=True)
    conflict = Column(Boolean,nullable=True)
    uj_premises = Column(Boolean,nullable=True)
    uj_facilities = Column(Boolean,nullable=True)
    uj_funding = Column(Boolean,nullable=True)
    vulnerable_comments_3 = Column(Text,nullable=True)
    apply_comments=Column(String,nullable=True)

    # Risk Rating and Justification
    risk_rating = Column(String(20),nullable=True)
    risk_justification = Column(Text,nullable=True)
    benefits_description = Column(Text,nullable=True)
    risk_mitigation = Column(Text,nullable=True)
    interviews_one = Column(Boolean, nullable=True)
    documents_one = Column(Boolean, nullable=True)
    other_sec2 = Column(String(255), nullable=True)
   
    # section 3
    title_provision=Column(String(255),nullable=True)
    abstract=Column(String(255),nullable=True)
    questions=Column(String(255),nullable=True)
    purpose_objectives=Column(String(255),nullable=True)
    # section 4
    grant_permission=Column(String,nullable=True)
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
     # 5.1
    quantitative = Column(Boolean, default=False)
    qualitative = Column(Boolean, default=False)
    mixed_methods = Column(Boolean, default=False)
    paradigm_explanation = Column(Text)

    # 5.2
    design = Column(Text)

    # 5.3 - Participant details
    participants_description = Column(Text)
    duration_timing = Column(String,nullable=True)
    contact_details_method = Column(Text)
    conflict_interest = Column(Boolean,default=False)
    conflict_explanation = Column(Text)
    population=Column(String,nullable=True)
    sampling_method=Column(String,nullable=True)
    sampling_size=Column(String,nullable=True)
    inclusion_criteria=Column(String,nullable=True)



    # 5.4 - Instruments
    data_methods = Column(PickleType, nullable=True) # Added - Stores list of selected methods
    questionnaire_type = Column(String(20))  # Self-designed / Existing
    permission_obtained = Column(Text)
    open_source = Column(Text)
    instrument_attachment_reason = Column(Text)
    data_collection_procedure = Column(Text)
    interview_type = Column(String(20))  # Structured / Semi-structured / Unstructured
    # in_depth=Column(String,nullable=True) #not using
    # semi_structured=Column(String,nullable=True) #not using
    # unstructured=Column(String,nullable=True) #not using
    interview_recording = Column(String)
    use_focus_groups = Column(Boolean, default=True)
    focus_recording = Column(String)
    #Added these 3 below
    observation_details = Column(Text)
    documents_details = Column(Text)
    other_details = Column(Text)
    data_collectors = Column(Text)
    intervention = Column(Boolean, default=True)
    intervention_details = Column(Text)
    sensitive_data = Column(Text)
    translator = Column(Boolean, default=True)
    translator_procedure = Column(Text)

    # 5.5 - Secondary Data
    uses_secondary_data = Column(Boolean, default=True)
    secondary_data_type = Column(String(10))  # public/private
    private_permission = Column(String(10))   # yes/no
    public_data_description = Column(Text)
    private_permission_file = Column(String(256))  # file path
    
    data_nature=Column(String(256))
    data_origin=Column(String(256))
    access_conditions=Column(String(256))
    personal_info=Column(String(256))
    personal_info_comment=Column(String(256))
    data_anonymized=Column(String(256))
    anonymization_comment=Column(String(256))
    permission_details=Column(String(256))
    shortcomings_reported=Column(String(256))
    limitations_reporting=Column(String(256))
    methodology_alignment=Column(String(256))
    data_acknowledgment=Column(String(256))
    ###
    secure_location=Column(String,nullable=True)
    password_protected=Column(String,nullable=True)
    protected_place=Column(String,nullable=True)
    retention=Column(String,nullable=True)
    # section 6
    informed_consent = Column(Text)
    data_storage = Column(PickleType)  # Stores list of selected options
    study_benefits = Column(Text)
    participant_risks = Column(Text)
    adverse_steps = Column(Text)
    community_participation = Column(Text)
    community_effects = Column(Text)
    privacy = Column(PickleType,nullable=True)  # Stores list of selected privacy practices
    # remove_identifiers=Column(String,nullable=True)
    # encryption=Column(String,nullable=True)
    # pseudonyms=Column(String,nullable=True)
    # focus_group_warning=Column(String,nullable=True)
    

    # 6.9 checklist items
    # Questions 6.9a to 6.9s — stored as a dictionary
    q6_9a = Column(Boolean,nullable=True,default=True)
    q6_9b=Column(Boolean,nullable=True,default=True)
    q6_9c=Column(Boolean,nullable=True,default=True)
    q6_9d=Column(Boolean,nullable=True,default=True)
    q6_9e=Column(Boolean,nullable=True,default=True)
    q6_9f=Column(Boolean,nullable=True,default=True)
    q6_9g=Column(Boolean,nullable=True,default=True)
    q6_9h=Column(Boolean,nullable=True,default=True)
    q6_9i=Column(Boolean,nullable=True,default=True)
    q6_9j=Column(Boolean,nullable=True,default=True)
    q6_9k=Column(Boolean,nullable=True,default=True)
    q6_9l=Column(Boolean,nullable=True,default=True)
    q6_9m=Column(Boolean,nullable=True,default=True)
    q6_9n=Column(Boolean,nullable=True,default=True)
    q6_9o=Column(Boolean,nullable=True,default=True)
    q6_9p=Column(Boolean,nullable=True,default=True)
    q6_9q=Column(Boolean,nullable=True,default=True)
    q6_9r=Column(Boolean,nullable=True,default=True)
    q6_9s=Column(Boolean,nullable=True,default=True)
   

    results_feedback = Column(Text,nullable=True)
    products_access = Column(Text,nullable=True)
    publication_plans = Column(Text,nullable=True)
    participant_comp = Column(Text,nullable=True)
    participant_costs = Column(Text,nullable=True)
    ethics_reporting = Column(Text,nullable=True)

    submitted_at = Column(DateTime(timezone=True),default=datetime.utcnow,nullable=True)

    declaration_name = Column(String(255), nullable=True)
    applicant_signature = Column(String(255), nullable=True)
    declaration_date = Column(DateTime, nullable=True)
    #this needs to be deleted
    supervisor_comments = Column(Text,nullable=True)###
    rejected_or_accepted=Column(Boolean,default=False)
    supervisor_date = Column(DateTime,nullable=True)
    org_permission_comment= Column(String(255),nullable=True)
    waiver_comment= Column(String(255),nullable=True)
    form_a_comment= Column(String(255),nullable=True)
    questions_comment= Column(String(255),nullable=True)
    consent_comment= Column(String(255),nullable=True)
    proposal_comment= Column(String(255),nullable=True)
    supervisor_feedback= Column(String(255),nullable=True)
    recommendation= Column(String(255),nullable=True)
    supervisor_signature = Column(String(255),nullable=True)
    signature_date= Column(DateTime,nullable=True)
    submitted=Column(Boolean,default=False)
    #this is working on supervisor site
    supervisor_date=Column(DateTime(255),nullable=True)
    supervisor_org_permission_status=Column(String(255),nullable=True)
    supervisor_org_permission_comments=Column(String(255),nullable=True)
    supervisor_waiver_status=Column(String(255),nullable=True)
    supervisor_waiver_comments=Column(String(255),nullable=True)
    supervisor_form_status=Column(String(255),nullable=True)
    supervisor_form_comments=Column(String(255),nullable=True)
    supervisor_questions_status=Column(String(255),nullable=True)
    supervisor_questions_comments=Column(String(255),nullable=True)
    supervisor_consent_status=Column(String(255),nullable=True)
    supervisor_consent_comments=Column(String(255),nullable=True)
    supervisor_proposal_status=Column(String(255),nullable=True)
    supervisor_proposal_comments=Column(String(255),nullable=True)
    supervisor_additional_comments=Column(String(255),nullable=True)
    supervisor_recommendation=Column(String(255),nullable=True)
    supervisor_supervisor_signature=Column(String(255),nullable=True)
    supervisor_signature_date=Column(DateTime,nullable=True)
    supervisor_form_status=Column(String(255),nullable=True)
    status=Column(String,nullable=True)
    submitted_to_rec=Column(Boolean,default=False)

    reviewer_name1=Column(String(255),nullable=True)
    reviewer_name2=Column(String(255),nullable=True)
    
    review_date=Column(String(255),nullable=True)
    review_org_permission_status=Column(String(255),nullable=True)
    review_org_permission_comments=Column(String(255),nullable=True)
    review_waiver_status=Column(String(255),nullable=True)
    review_waiver_comments=Column(String(255),nullable=True)
    review_form_status=Column(String(255),nullable=True)
    review_form_comments=Column(String(255),nullable=True)
    review_questions_status=Column(String(255),nullable=True)
    review_questions_comments=Column(String(255),nullable=True)
    review_consent_status=Column(String(255),nullable=True)
    review_consent_comments=Column(String(255),nullable=True)
    review_proposal_status=Column(String(255),nullable=True)
    review_proposal_comments=Column(String(255),nullable=True)
    review_additional_comments=Column(String(255),nullable=True)
    review_recommendation=Column(String(255),nullable=True)
    review_supervisor_signature=Column(String(255),nullable=True)
    review_signature_date=Column(DateTime,nullable=True)
    review_status=Column(Boolean,default=False)
    form_review_comment=Column(String(255),nullable=True)
    form_reviewed_by=Column(String,nullable=True)



    review_date1=Column(String(255),nullable=True)
    review_org_permission_status1=Column(String(255),nullable=True)
    review_org_permission_comments1=Column(String(255),nullable=True)
    review_waiver_status1=Column(String(255),nullable=True)
    review_waiver_comments1=Column(String(255),nullable=True)
    review_form_status1=Column(String(255),nullable=True)
    review_form_comments1=Column(String(255),nullable=True)
    review_questions_status1=Column(String(255),nullable=True)
    review_questions_comments1=Column(String(255),nullable=True)
    review_consent_status1=Column(String(255),nullable=True)
    review_consent_comments1=Column(String(255),nullable=True)
    review_proposal_status1=Column(String(255),nullable=True)
    review_proposal_comments1=Column(String(255),nullable=True)
    review_additional_comments1=Column(String(255),nullable=True)
    review_recommendation1=Column(String(255),nullable=True)
    review_supervisor_signature1=Column(String(255),nullable=True)
    review_signature_date1=Column(DateTime,nullable=True)
    review_status1=Column(Boolean,default=False)
    form_review_comment1=Column(String(255),nullable=True)
    form_reviewed_by1=Column(String,nullable=True)

    rec_comments=Column(String,nullable=True)
    rec_status=Column(String,nullable=True)
    rec_date=Column(DateTime,server_default=func.now())

    certificate_code=Column(String(255),nullable=True)
    certificate_issued=Column(DateTime,nullable=True)
    
    certificate_valid_years=Column(String,nullable=True)
    certificate_end_date=Column(DateTime)
    certificate_issuer=Column(String(255),nullable=True)
    certificate_email=Column(String(255),nullable=True)
    certificate_received=Column(Boolean,default=False)
    certificate_heading=Column(String,default='ETHICAL APPROVAL GRANTED FOR RESEARCH PROJECT')
    certificate_modified=Column(Boolean,default=False)
    certificate_condition_1=Column(String(255),nullable=True)
    

    pdf_file_path=Column(String,nullable=True)
    def __repr__(self):
        return f'<FormA {self.applicant_name} ({self.student_number})>'
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}



class FormB(Base):
    __tablename__ = "form_b"
    form_id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255),ForeignKey("users.user_id"), nullable=False)
    form_a_requirements = relationship(
        "FormARequirements",
        primaryjoin="FormB.user_id == foreign(FormARequirements.user_id)",
        back_populates="form_b",
        uselist=False  # Assuming one requirements record per FormA/user
    )
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

    submitted_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    submitted=Column(Boolean,default=False)

    rejected_or_accepted=Column(Boolean,default=False)
    supervisor_date = Column(DateTime,nullable=True)
    org_permission_comment= Column(String(255),nullable=True)
    waiver_comment= Column(String(255),nullable=True)
    form_a_comment= Column(String(255),nullable=True)
    questions_comment= Column(String(255),nullable=True)
    consent_comment= Column(String(255),nullable=True)
    proposal_comment= Column(String(255),nullable=True)
    supervisor_feedback= Column(String(255),nullable=True)
    recommendation= Column(String(255),nullable=True)
    supervisor_signature = Column(String(255),nullable=True)
    signature_date= Column(DateTime,nullable=True)

    #this is working on supervisor site
    supervisor_date=Column(DateTime,nullable=True)
    supervisor_org_permission_status=Column(String(255),nullable=True)
    supervisor_org_permission_comments=Column(String(255),nullable=True)
    supervisor_waiver_status=Column(String(255),nullable=True)
    supervisor_waiver_comments=Column(String(255),nullable=True)
    supervisor_form_status=Column(String(255),nullable=True)
    supervisor_form_comments=Column(String(255),nullable=True)
    supervisor_questions_status=Column(String(255),nullable=True)
    supervisor_questions_comments=Column(String(255),nullable=True)
    supervisor_consent_status=Column(String(255),nullable=True)
    supervisor_consent_comments=Column(String(255),nullable=True)
    supervisor_proposal_status=Column(String(255),nullable=True)
    supervisor_proposal_comments=Column(String(255),nullable=True)
    supervisor_additional_comments=Column(String(255),nullable=True)
    supervisor_recommendation=Column(String(255),nullable=True)
    supervisor_supervisor_signature=Column(String(255),nullable=True)
    supervisor_signature_date=Column(DateTime,nullable=True)
    supervisor_form_status=Column(String(255),nullable=True)
    status=Column(String,nullable=True)
    submitted_to_rec=Column(Boolean,default=False)

    reviewer_name1=Column(String(255),nullable=True)
    reviewer_name2=Column(String(255),nullable=True)

    review_date=Column(String(255),nullable=True)
    review_org_permission_status=Column(String(255),nullable=True)
    review_org_permission_comments=Column(String(255),nullable=True)
    review_waiver_status=Column(String(255),nullable=True)
    review_waiver_comments=Column(String(255),nullable=True)
    review_form_status=Column(String(255),nullable=True)
    review_form_comments=Column(String(255),nullable=True)
    review_questions_status=Column(String(255),nullable=True)
    review_questions_comments=Column(String(255),nullable=True)
    review_consent_status=Column(String(255),nullable=True)
    review_consent_comments=Column(String(255),nullable=True)
    review_proposal_status=Column(String(255),nullable=True)
    review_proposal_comments=Column(String(255),nullable=True)
    review_additional_comments=Column(String(255),nullable=True)
    review_recommendation=Column(String(255),nullable=True)
    review_supervisor_signature=Column(String(255),nullable=True)
    review_signature_date=Column(DateTime,nullable=True)
    review_status=Column(Boolean,default=False)
    form_review_comment=Column(String(255),nullable=True)
    form_reviewed_by=Column(String,nullable=True)

    
    review_date1=Column(String(255),nullable=True)
    review_org_permission_status1=Column(String(255),nullable=True)
    review_org_permission_comments1=Column(String(255),nullable=True)
    review_waiver_status1=Column(String(255),nullable=True)
    review_waiver_comments1=Column(String(255),nullable=True)
    review_form_status1=Column(String(255),nullable=True)
    review_form_comments1=Column(String(255),nullable=True)
    review_questions_status1=Column(String(255),nullable=True)
    review_questions_comments1=Column(String(255),nullable=True)
    review_consent_status1=Column(String(255),nullable=True)
    review_consent_comments1=Column(String(255),nullable=True)
    review_proposal_status1=Column(String(255),nullable=True)
    review_proposal_comments1=Column(String(255),nullable=True)
    review_additional_comments1=Column(String(255),nullable=True)
    review_recommendation1=Column(String(255),nullable=True)
    review_supervisor_signature1=Column(String(255),nullable=True)
    review_signature_date1=Column(DateTime,nullable=True)
    review_status1=Column(Boolean,default=False)
    form_review_comment1=Column(String(255),nullable=True)
    form_reviewed_by1=Column(String,nullable=True)


    rec_comments=Column(String,nullable=True)
    rec_status=Column(String,nullable=True)
    rec_date=Column(DateTime,default=datetime.utcnow,nullable=True)

    certificate_code=Column(String(255),nullable=True)
    certificate_issued=Column(DateTime,nullable=True)

    certificate_valid_years=Column(String,nullable=True)
    certificate_end_date=Column(DateTime)
    certificate_issuer=Column(String(255),nullable=True)
    certificate_email=Column(String(255),nullable=True)
    certificate_received=Column(Boolean,default=False)
    certificate_heading=Column(String,default='ETHICAL APPROVAL GRANTED FOR RESEARCH PROJECT')
    certificate_modified=Column(Boolean,default=False)
    certificate_condition_1=Column(String(255),nullable=True)
    

    pdf_file_path=Column(String,nullable=True)
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
    

class FormC(Base):
    __tablename__ = "form_c"
    form_id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255),ForeignKey("users.user_id"), nullable=False)
    form_a_requirements = relationship(
        "FormARequirements",
        primaryjoin="FormC.user_id == foreign(FormARequirements.user_id)",
        back_populates="form_c",
        uselist=False  # Assuming one requirements record per FormA/user
    )
    # Section 1
    applicant_name = Column(String(100))
    student_number = Column(String(50))
    institution = Column(String(100))
    department = Column(String(100))
    degree = Column(String(100))
    project_title = Column(String(200))
    mobile_number = Column(String(20))
    email_address = Column(String(120))
    supervisor_name = Column(String(200))
    supervisor_email = Column(String(200))

    # Section 2
    # Vulnerable Populations
    vulnerable = Column(Boolean, default=False)
    age_under_18_or_over_65 = Column(Boolean, default=False)
    uj_employees = Column(Boolean, default=False)
    non_vulnerable_context = Column(Boolean, default=False)
    non_english = Column(Boolean, default=False)
    own_students = Column(Boolean, default=False)
    poverty = Column(Boolean, default=False)
    no_education = Column(Boolean, default=False)
    vulnerable_other_description = Column(Text, nullable=True)
    vulnerable_comments=Column(String,nullable=True)
    # Research Activities Risk Assessment
    consent_violation = Column(Boolean, default=False)
    discomfiture = Column(Boolean, default=False)
    deception = Column(Boolean, default=False)
    sensitive_issues = Column(Boolean, default=False)
    prejudicial_info = Column(Boolean, default=False)
    intrusive = Column(Boolean, default=False)
    illegal = Column(Boolean, default=False)
    direct_social_info = Column(Boolean, default=False)
    identifiable_records = Column(Boolean, default=False)
    psychology_tests = Column(Boolean, default=False)
    researcher_risk = Column(Boolean, default=False)
    activity_other_description = Column(Text, nullable=True)
    activity_comments=Column(String,nullable=True)
    # Additional Research Considerations
    incentives = Column(Boolean, default=True)
    participant_costs = Column(Boolean, default=False)
    researcher_interest = Column(Boolean, default=False)
    conflict_of_interest = Column(Boolean, default=False)
    uj_premises = Column(Boolean, default=False)
    uj_facilities = Column(Boolean, default=False)
    uj_funding = Column(Boolean, default=False)

    # - Risk Assessment 
    consideration_comments=Column(String,nullable=True)
    vulnerable_groups = Column(String,nullable=True)
    vulnerable_comments = Column(Text,nullable=True)
    research_activities = Column(Text,nullable=True)
    activities_comments = Column(Text,nullable=True)
    additional_considerations = Column(Text,nullable=True)
    considerations_comments = Column(Text,nullable=True)
    risk_level = Column(String(20),nullable=True)
    risk_justification = Column(Text,nullable=True)
    risk_benefits = Column(Text,nullable=True)
    risk_mitigation = Column(Text,nullable=True)

    # Section 3
    summary_title = Column(Text,nullable=True)
    executive_summary = Column(Text,nullable=True)
    research_questions = Column(Text,nullable=True)
    research_purpose = Column(Text,nullable=True)
    secondary_data_info = Column(Text,nullable=True)
    exemption_reason = Column(Text,nullable=True)

    # Section 4 - Declaration
    declaration_name = Column(String(200),nullable=True)
    full_name = Column(String(200),nullable=True)
    submission_date = Column(DateTime(timezone=True),default=datetime.utcnow,nullable=True)
    submitted=Column(Boolean,default=False)
    
    
    supervisor_comments = Column(Text,nullable=True)
    rejected_or_accepted=Column(Boolean,default=False)
    supervisor_date = Column(DateTime,default=datetime.utcnow,nullable=True)
    org_permission_comment= Column(String(255),nullable=True)
    waiver_comment= Column(String(255),nullable=True)
    form_a_comment= Column(String(255),nullable=True)
    questions_comment= Column(String(255),nullable=True)
    consent_comment= Column(String(255),nullable=True)
    proposal_comment= Column(String(255),nullable=True)
    supervisor_feedback= Column(String(255),nullable=True)
    recommendation= Column(String(255),nullable=True)
    supervisor_signature = Column(String(255),nullable=True)
    signature_date= Column(DateTime,nullable=True)
    
    #this is working on supervisor site
    supervisor_date=Column(DateTime,nullable=True)
    supervisor_org_permission_status=Column(String(255),nullable=True)
    supervisor_org_permission_comments=Column(String(255),nullable=True)
    supervisor_waiver_status=Column(String(255),nullable=True)
    supervisor_waiver_comments=Column(String(255),nullable=True)
    supervisor_form_status=Column(String(255),nullable=True)
    supervisor_form_comments=Column(String(255),nullable=True)
    supervisor_questions_status=Column(String(255),nullable=True)
    supervisor_questions_comments=Column(String(255),nullable=True)
    supervisor_consent_status=Column(String(255),nullable=True)
    supervisor_consent_comments=Column(String(255),nullable=True)
    supervisor_proposal_status=Column(String(255),nullable=True)
    supervisor_proposal_comments=Column(String(255),nullable=True)
    supervisor_additional_comments=Column(String(255),nullable=True)
    supervisor_recommendation=Column(String(255),nullable=True)
    supervisor_supervisor_signature=Column(String(255),nullable=True)
    supervisor_signature_date=Column(DateTime,nullable=True)
    status=Column(String,nullable=True)
    submitted_to_rec=Column(Boolean,default=False)

    reviewer_name1=Column(String(255),nullable=True)
    reviewer_name2=Column(String(255),nullable=True)

    review_date=Column(String(255),nullable=True)
    review_org_permission_status=Column(String(255),nullable=True)
    review_org_permission_comments=Column(String(255),nullable=True)
    review_waiver_status=Column(String(255),nullable=True)
    review_waiver_comments=Column(String(255),nullable=True)
    review_form_status=Column(String(255),nullable=True)
    review_form_comments=Column(String(255),nullable=True)
    review_questions_status=Column(String(255),nullable=True)
    review_questions_comments=Column(String(255),nullable=True)
    review_consent_status=Column(String(255),nullable=True)
    review_consent_comments=Column(String(255),nullable=True)
    review_proposal_status=Column(String(255),nullable=True)
    review_proposal_comments=Column(String(255),nullable=True)
    review_additional_comments=Column(String(255),nullable=True)
    review_recommendation=Column(String(255),nullable=True)
    review_supervisor_signature=Column(String(255),nullable=True)
    review_signature_date=Column(DateTime,nullable=True)
    review_status=Column(Boolean,default=False)
    form_review_comment=Column(String(255),nullable=True)
    form_reviewed_by=Column(String,nullable=True)


    review_date1=Column(String(255),nullable=True)
    review_org_permission_status1=Column(String(255),nullable=True)
    review_org_permission_comments1=Column(String(255),nullable=True)
    review_waiver_status1=Column(String(255),nullable=True)
    review_waiver_comments1=Column(String(255),nullable=True)
    review_form_status1=Column(String(255),nullable=True)
    review_form_comments1=Column(String(255),nullable=True)
    review_questions_status1=Column(String(255),nullable=True)
    review_questions_comments1=Column(String(255),nullable=True)
    review_consent_status1=Column(String(255),nullable=True)
    review_consent_comments1=Column(String(255),nullable=True)
    review_proposal_status1=Column(String(255),nullable=True)
    review_proposal_comments1=Column(String(255),nullable=True)
    review_additional_comments1=Column(String(255),nullable=True)
    review_recommendation1=Column(String(255),nullable=True)
    review_supervisor_signature1=Column(String(255),nullable=True)
    review_signature_date1=Column(DateTime,nullable=True)
    review_status1=Column(Boolean,default=False)
    form_review_comment1=Column(String(255),nullable=True)
    form_reviewed_by1=Column(String,nullable=True)


    rec_comments=Column(String,nullable=True)
    rec_status=Column(String,nullable=True)
    rec_date=Column(DateTime,server_default=func.now(),nullable=True)

    certificate_code=Column(String(255),nullable=True)
    certificate_issued=Column(DateTime,nullable=True)

    certificate_valid_years=Column(String,nullable=True)
    certificate_end_date=Column(DateTime)
    certificate_issuer=Column(String(255),nullable=True)
    certificate_email=Column(String(255),nullable=True)
    certificate_received=Column(Boolean,default=False)
    certificate_heading=Column(String,default='ETHICAL APPROVAL GRANTED FOR RESEARCH PROJECT')
    certificate_modified=Column(Boolean,default=False)
    certificate_condition_1=Column(String(255),nullable=True)
    

    pdf_file_path=Column(String,nullable=True)
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class Rec(Base):
    __tablename__ = "rec"
    id = Column(String(255), primary_key=True, default=generate_uuid)
    rec_id = Column(String(255), nullable=True)
    form_id = Column(String(255), nullable=True)
    full_name = Column(String, nullable=True)
    rec_comments = Column(String, nullable=True)
    rec_status = Column(String, nullable=True)
    rec_date = Column(DateTime, server_default=func.now(), nullable=True)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class FormD(Base):
    __tablename__ = "form_d"

    #Schema
    form_id = Column(String(255), primary_key=True, default=generate_uuid)
    user_id = Column(String(255), nullable=True)
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
class Watched(Base):
    __tablename__ = "watched"
    watched_id=Column(String(255),primary_key=True, default=generate_uuid)
    user_id=Column(String(255),nullable=False)
    watched=Column(Boolean,default=False)
    def to_dict(self):
         return {
            "watched_id": self.watched_id,
            "user_id": self.user_id,
            "watched": self.watched
        }

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
Base.metadata.create_all(engine)
