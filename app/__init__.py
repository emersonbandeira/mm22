from flask import Flask, jsonify
import logging
from flask_mail import Mail

app = Flask(__name__)

app.config['DEBUG']=True
app.config.from_object("config")

mail = Mail(app)

from .routes import routes