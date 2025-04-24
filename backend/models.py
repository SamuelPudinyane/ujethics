from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, Enum, DateTime
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
import enum
import uuid
import bcrypt
import datetime

mySQL_string = 'mysql+pymysql://root:password@localhost/ethics'
sqlite_string = "sqlite+pysqlite:///ethics.db"

engine = create_engine(sqlite_string, echo=False)

Session = sessionmaker(bind=engine)
db_session = Session()

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

# Create an enum class for roles, makes it easy to change at one place if there be additional roles.
class UserRole(enum.Enum):
    STUDENT = "student"
    SUPERVISOR = "supervisor"
    ADMIN = "admin"
    REC = "rec"         #Research Ethics committe
    REVIEWER = "reviewer"


class User(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True, default=generate_uuid)
    full_name = Column(String, nullable=False)
    student_number = Column(Integer, nullable=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    supervisor_id = Column(String, nullable=True)
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
    def hash_password(password:str)->str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password:str)->bool:
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
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

Base.metadata.create_all(engine)

# try:
#     user1 = User("Prof Albert Einstein", None, "eistein@uj.ac.za", "1234", None, "supervisor" )
#     db_session.add(user1)
#     db_session.commit()
# except Exception as e:
#     print("Failed to store user. \n", e)