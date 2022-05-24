from flask import Flask, jsonify
import logging

app = Flask(__name__)

app.config['DEBUG']=True
app.config.from_object("config")

from .routes import routes