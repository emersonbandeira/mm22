from sqlalchemy import Column, Integer, String
from config import Base

class Profile(Base):
    __tablename__ = 'profile'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)


    def __repr__(self):
        return "<Profile(name='%s')>" % (self.name)
        