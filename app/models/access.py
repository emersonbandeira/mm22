from cgitb import text
from datetime import date
from MySQLdb import Timestamp
from sqlalchemy import Column, Integer, String, TIMESTAMP, ForeignKey
from config import Base

class Access(Base):
    __tablename__ = 'access'

    id = Column(Integer, primary_key=True)
    timestamped = Column(TIMESTAMP)
    IP = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))

    def __repr__(self):
        return "<Acesso(IP='%s')>" % (self.IP)
