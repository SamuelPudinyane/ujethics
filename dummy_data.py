from models import User,db_session   # adjust this import as needed

users = [
    User(
        full_name="Dr. Sarah Molefe",
        email="sarah.molefe@uj.ac.za",
        password="supervisor1",
        student_number="",
        supervisor_id="",
        role="SUPERVISOR"
    ),
    User(
        full_name="Prof. Kabelo Mokoena",
        email="kabelo.mokoena@uj.ac.za",
        password="supervisor2",
        student_number="",
        supervisor_id="",
        role="ADMIN"
    ),
    User(
        full_name="Dr. Ayanda Dlamini",
        email="ayanda.dlamini@uj.ac.za",
        password="supervisor3",
        student_number="",
        supervisor_id="",
        role="DEAN"
    ),
    User(
        full_name="Prof. Neo Masemola",
        email="neo.masemola@uj.ac.za",
        password="supervisor4",
        student_number="",
        supervisor_id="",
        role="REC"
    ),
    User(
        full_name="Dr. Linda Mthembu",
        email="linda.mthembu@uj.ac.za",
        password="supervisor5",
        student_number="",
        supervisor_id="",
        role="REVIEWER"
    )
]

# Add all to the session and commit
db_session.add_all(users)
db_session.commit()



"""
Awaiting for review
if forma.rejected_or_accepted and not forma.review_date 

forma.rec_status
if forma.rec_status and forma.risk_rating != 'low'


Certificate Issued
if forma.certificate_issued

"""