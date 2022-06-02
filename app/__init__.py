from flask import Flask, jsonify
import logging
from flask_mail import Mail
from flask_login import LoginManager, login_manager
from app.models.user import User
from config import mysql_session
from flask_bootstrap import Bootstrap



app = Flask(__name__)

app.config['DEBUG']=True
app.config.from_object("config")

#Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return mysql_session.query(User).filter_by(public_id=user_id).first()


mail = Mail(app)

from .routes import routes