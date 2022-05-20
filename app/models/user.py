from sqlalchemy import Column, Integer, String
from config import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    public_id = Column(Integer)
    name = Column(String)
    email = Column(String)
    password = Column(String)

    def __repr__(self):
        return "<User(name='%s', email='%s', public_id='%s')>" % (
                            self.name, self.email, self.public_id)