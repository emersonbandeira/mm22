from sqlalchemy import Column, Integer, String,  ForeignKey, TIMESTAMP, Boolean
from config import Base

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    public_id = Column(Integer)
    name = Column(String)
    email = Column(String)
    password = Column(String)
    accept_tos = Column(Integer)
    profile_id = Column(Integer, ForeignKey('profile.id'))
    created = Column(TIMESTAMP)
    activated = Column(TIMESTAMP)

    def __repr__(self):
        return "<User(name='%s', email='%s', public_id='%s')>" % (
                            self.name, self.email, self.public_id)

    def is_authenticated(self):
        return True

    def is_active(self):   
        return True           

    def is_anonymous(self):
        return False      
    
    def get_id(self):
        return str(self.public_id)
    
