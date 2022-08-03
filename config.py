import logging
import os
from decouple import config
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote
import socket

ENGINE_PARM=config('ENGINE_PARM')

def configure_db(pwd):
    SQLALCHEMY_DATABASE_URI=f"mysql://meme:{pwd}@localhost:3306/mm22"
    ENGINE_PARM=f"mysql://meme:{pwd}@127.0.0.1:3306/mm22"

BASE_DIR=os.path.abspath('.')

DEBUG=config('DEBUG', cast=bool)

SECRET_KEY=config('SECRET_KEY') 

SENDER_MAIL=config('SENDER_MAIL')

MAIL_USERNAME=config('MAIL_USERNAME')
MAIL_PASSWORD=config('MAIL_PASSWORD')

DB_PASS=config('DB_PASS')

configure_db(DB_PASS)

SQLALCHEMY_TRACK_NOTIFICATIONS=False

engine = create_engine(ENGINE_PARM, echo=True, future=True)

logging.warning(engine.__module__)

Base =  declarative_base()

Session = sessionmaker(bind=engine)
mysql_session = Session()

logging.warning('session {}'.format(mysql_session) )

MAIL_SERVER='smtp.gmail.com'
MAIL_PORT=465
MAIL_USE_TLS=False
MAIL_USE_SSL=True

MY_IP = "127.0.0.1" #socket.gethostbyname(socket.gethostname())

UPLOAD_FOLDER = './app/static/uploads'

