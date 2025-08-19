from models import User,db_session   # adjust this import as needed

users = [
    User(
        full_name="Dr. Sarah Molefe",
        email="sarah.molefe@uj.ac.za",
        password="supervisor1",
        student_number=6546545,
        supervisor_id="",
        role="SUPERVISOR"
    ),
    User(
        full_name="Prof. Kabelo Mokoena",
        email="kabelo.mokoena@uj.ac.za",
        password="supervisor2",
        student_number=646545,
        supervisor_id="",
        role="ADMIN"
    ),
    # User(
    #     full_name="Dr. Ayanda Dlamini",
    #     email="ayanda.dlamini@uj.ac.za",
    #     password="supervisor3",
    #     student_number=645645,
    #     supervisor_id="",
    #     role="ADMIN"
    # ),
    User(
        full_name="Prof. Neo Masemola",
        email="neo.masemola@uj.ac.za",
        password="supervisor4",
        student_number=1665151,
        supervisor_id="",
        role="REVIEWER"
    ),
    User(
        full_name="Dr. Linda Mthembu",
        email="linda.mthembu@uj.ac.za",
        password="supervisor5",
        student_number=1651151,
        supervisor_id="",
        role="REVIEWER"
    ),
    User(
        full_name="Dr. Michael Phillips",
        email="michael.phillips@uj.ac.za",
        password="Michael@1234",
        student_number=16516551,
        supervisor_id="",
        role="REVIEWER"
    ),
    User(
        full_name="Dr. Robin May",
        email="robin.may@uj.ac.za",
        password="Robin@1234",
        student_number=16516551,
        supervisor_id="",
        role="REVIEWER"
    ),
    User(
        full_name="Dr. Jane Doe",
        email="jane.doe@uj.ac.za",
        password="Jane@1234",
        student_number=16516551,
        supervisor_id="",
        role="REVIEWER"
    ),


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