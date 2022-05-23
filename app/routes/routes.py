from sqlite3 import Timestamp
from app import app
from flask import jsonify, request, make_response
from crypt import methods
from werkzeug.security import generate_password_hash,check_password_hash
from lib2to3.refactor import RefactoringTool
from app.models import servico_usuario
from app.models.profile import Profile
from config import session
import logging
from functools import wraps
import jwt
import datetime
import uuid
from app.models.user import User
from app.models.access import Access



def token_required(f):
     @wraps(f)
     def decorator(*args, **kwargs):
          token = None
          if 'x-access-tokens' in request.headers:
               token = request.headers['x-access-tokens']

          logging.warning('token_required')

          if not token:
               return jsonify({'message': 'a valid token is missing'})
          try:
               data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
               current_user = session.query(User).filter_by(public_id=data['public_id']).first()

               logging.warning('public_id2: [{}]'.format(data.get('public_id')))

          except:
               return jsonify({'message': 'token is invalid'})
 
          return f(current_user, *args, **kwargs)
     
     return decorator

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


@token_required
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
     user.public_id = str(uuid.uuid4())
     user.profile_id = 2
     user.password = generate_password_hash(password)

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

     if not auth or not auth.username or not auth.password: 
       return make_response('could not verify', 401, {'Authentication': 'login required"'})   
 
     user = session.query(User).filter_by(name=auth.username).first()

     hashed_pass = generate_password_hash(auth.password)
     logging.warning('user.name: {}'.format(user.name))

     if check_password_hash(user.password, auth.password):
          token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
          acesso = Access()
          acesso.IP = request.environ.get('HTTP_X_REAL_IP', request.remote_addr) 
          acesso.user_id = user.id
          acesso.timestamped = datetime.datetime.now()
          session.add(acesso)
          session.commit()

          return jsonify({'token' : token})
 
     return make_response('could not verify',  401, {'Authentication': '"login required"'})

