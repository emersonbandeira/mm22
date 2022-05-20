from crypt import methods
from lib2to3.refactor import RefactoringTool
from app import app
from flask import jsonify, request, redirect, url_for
from app.models import servico_usuario
from config import session
import logging


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



@app.route('/users', methods=['POST'])
def users():
     retorno = ''
     our_user = session.query(User).filter_by(name='meme').first() 
     
     logging.warning(our_user.name)

     if our_user:
          retorno = jsonify('user:',our_user.name)

     return retorno