import logging
import os
from decouple import config
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote

BASE_DIR = os.path.abspath('.')

DEBUG = config('DEBUG', cast=bool)

SECRET_KEY = config('SECRET_KEY') 


SQLALCHEMY_DATABASE_URI=('mysql://meme%s@localhost:3306/mm22' % quote('badpass'))
SQLALCHEMY_TRACK_NOTIFICATIONS=False

#create_engine('postgres://user:%s@host/database' % urlquote('badpass'))
engine = create_engine( 'mysql://meme:%s@127.0.0.1:3306/mm22' % quote('m3m3@@') , echo=True, future=True)

logging.warning(engine.__module__)

Base =  declarative_base()

Session = sessionmaker(bind=engine)
mysql_session = Session()

logging.warning('session {}'.format(mysql_session) )

#def get_db_connection():
#    cnx = mysql.connector.connect(user='meme', password='m3m3@@',
#                              host='localhost',
#                              database='mm22')
#    return cnx


