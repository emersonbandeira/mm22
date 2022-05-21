from crypt import methods
from hashlib import sha256
from lib2to3.refactor import RefactoringTool
from app import app
from flask import jsonify, request, redirect, url_for
from app.models import servico_usuario
from app.models.profile import Profile
from config import session
import logging
import hashlib


from app.models.user import User


@app.route( '/', methods=['GET'])
def root():
     return jsonify({'message':'Hello!'})

@app.route('/cadastrar', methods=['POST'])
def cadastrar():
     email = request.args.get('email')
     nome = request.args.get('nome')
     senha = request.args.get('senha')
     retorno = servico_usuario.cadastrar_usuario(email, nome, senha)
     return retorno

@app.route('/usuario', methods=['POST', 'GET'])
def obtem_usuario():
    
     retorno = jsonify({'message':'Usuário inválido!'})

     id = request.args.get('id')
     logging.warning('obtem_usuario {}'.format(id))

     if id:
          logging.warning('recuperar: {}'.format(id))
          retorno = servico_usuario.obtem_usuario(id)
     
     return retorno

@app.route('/usuarios', methods=['POST', 'GET'])
def obtem_usuarios():

     logging.warning('obtem_usuarios ')

     retorno = servico_usuario.obtem_usuarios()
     
     return retorno


@app.route('/testerec', methods=['POST'])
def testerec():
     id = request.args.get('id')
     logging.warning('testerec {}'.format(id))
     return jsonify({'message':'testerec'})



@app.route('/user', methods=['POST'])
def user():
     retorno = ''

     user = request.args.get('user')
     id_parm = request.args.get('id')

     if user:
          our_user = session.query(User).filter_by(name=user).first()
          logging.warning(our_user.name)

     elif id:
          our_user = session.query(User).filter_by(id=id_parm).first()
          logging.warning(our_user.name)

     if our_user:
          retorno = jsonify('user:',our_user.name)

     return retorno


@app.route('/register', methods=['POST'])
def register():
     retorno = ''

     password = request.args.get('password')

     user = User()
     user.name = request.args.get('name')
     user.email = request.args.get('email')
     user.profile_id = 2
     user.password = hashlib.sha256(password.encode('utf-8')).hexdigest()

     profile = Profile()
     profile.id = 2
     user.profile = profile

     session.add(user)
     session.commit()

     return jsonify({'message':'Sucess!'})
     
@app.route('/login', methods=['POST'])
def login():
     retorno = ''

     auth = request.authorization

     if auth:
          logging.warning(auth.username)


     return jsonify({'message':'Sucess!'})
