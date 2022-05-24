from flask import jsonify
#from config import get_db_connection
import logging
import hashlib


def cadastrar_usuario(email, nome, senha):
    conn = get_db_connection()
    cur = conn.cursor()
    hashed_password = hashlib.sha256(senha.encode('utf-8')).hexdigest()
    cur.execute("INSERT INTO users (name, email, password) VALUES (%s,%s,%s)", (nome, email, hashed_password))
    conn.commit()
    cur.close()    
    return jsonify({'message':'Cadastrado com sucesso!'})

def obtem_usuario(id):
    
    logging.warning('recuperar usuario {}'.format(id))
    
    retorno = jsonify({'message':'Parametro invalido'})

    if id != "":
        logging.warning('conectando...')
#        conn = get_db_connection()
#        if conn:
#            logging.warning('conectou')
#            cur = conn.cursor()
#            logging.warning('query {}'.format(id))
#            cur.execute('SELECT * FROM users WHERE id = {}'.format(id))
#            data = cur.fetchall()
#            logging.warning('data: {}'.format(data))
#            cur.close()
#             retorno = jsonify({'user':data})           
    
    return retorno

# OBTEM USUARIOS

def obtem_usuarios():
    
    logging.warning('recuperar usuarios')
    
    retorno = jsonify({'message':'Parametro invalido'})

    logging.warning('conectando...')
#    conn = get_db_connection()
#    if conn:
#        logging.warning('conectou')
#        cur = conn.cursor()
#        cur.execute('SELECT * FROM users')
#        data = cur.fetchall()
#        logging.warning('data: {}'.format(data))
#        cur.close()
#        retorno = jsonify({'user':data})           
    
    return retorno
