from sqlalchemy import Column, Integer, String, Boolean

from app.models.base import Base

class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    password = Column(String)
    coins = Column(Integer)
    aboutme = Column(String)
    admin = Column(Boolean)

    def get_coins(self):
        return self.coins

    def credit_coins(self, i):
        self.coins += i

    def debit_coins(self, i):
        self.coins -= i

    def update_aboutme(self, text):
        self.aboutme = text

    def set_coins(self, amount):
        self.coins = amount

def create_user(db, username, password, admin=False):
    user = User(
        username=username,
        password=password,
        coins=100,
        aboutme="",
        admin=admin,
    )
    db.add(user)
    return user

def get_user(db, username):
    return db.query(User).filter_by(username=username).first()

