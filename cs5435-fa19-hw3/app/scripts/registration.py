from csv import reader

from app.models.user import create_user

REGISTRATION_PATH = "app/scripts/registration.csv"

def register_users(db):
    create_user(db, "attacker", "attacker")
    create_user(db, "victim", "victim")
    create_user(db, "admin", "admin", admin=True)

