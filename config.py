import logging
import os
import string
from click import echo
from decouple import config
#import mysql.connector
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
#from urlquote import quote
from urllib.parse import quote
 

BASE_DIR = os.path.abspath('.')

DEBUG = config('DEBUG', cast=bool)

SECRET_KEY = config('SECRET_KEY') or \
    ''.join(random.choice(string.ascii_letters) for i in range(42))


SQLALCHEMY_DATABASE_URI=('mysql://meme%s@localhost:3306/mm22' % quote('badpass'))
SQLALCHEMY_TRACK_NOTIFICATIONS=False

#create_engine('postgres://user:%s@host/database' % urlquote('badpass'))
engine = create_engine( 'mysql://meme:%s@127.0.0.1:3306/mm22' % quote('m3m3@@') , echo=True, future=True)

logging.warning(engine.__module__)

Base =  declarative_base()

Session = sessionmaker(bind=engine)
session = Session()

logging.warning('session {}'.format(session) )

#def get_db_connection():
#    cnx = mysql.connector.connect(user='meme', password='m3m3@@',
#                              host='localhost',
#                              database='mm22')
#    return cnx


