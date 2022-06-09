import os
import collections
from ctypes import sizeof
from tokenize import PlainToken
from app import app
from flask import jsonify, request, make_response, render_template, redirect, flash, session, url_for, g, abort, Response
from flask_mail import Message
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
from app.models.profile import Profile
from config import MY_IP, mysql_session
import logging
from functools import wraps
import jwt
import datetime
import uuid
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, desc

from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib.pyplot as plt
import numpy as np
import io

from app.models.user import User
from app.models.access import Access
from app.forms import RegistrationForm, ProfileForm, LoginForm, UserUpdateForm
from app import mail
from app.utils import get_redirect_target, is_safe_url, redirect_back, allowed_file



def token_required(f):

     logging.warning('token_required... 1')

     @wraps(f)
     def decorator(*args, **kwargs):
          token = None
          if 'x-access-tokens' in request.headers:
               token = request.headers['x-access-tokens']

          logging.warning('token_required... 2')

          if not token:
               return jsonify({'message': 'a valid token is missing'})
          try:
               data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
               current_user = session.query(User).filter_by(public_id=data['public_id']).first()

               logging.warning('public_id: [{}]'.format(data.get('public_id')))

          except:
               return jsonify({'message': 'token is invalid'})
 
          return f(current_user, *args, **kwargs)
     
     return decorator


@app.route( '/', methods=['GET'])
@app.route('/index')
@login_required
def index():
     IP = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)        
     logging.warning('cuser: [{}] ({})'.format(current_user.name, IP))
     return render_template('index.html',IP=IP)

@app.route('/login', methods=('GET', 'POST'))
def login():

     form = LoginForm(request.form)
     logging.warning('login iniciou...')

     if request.method == 'POST' and form.validate():

          if not request.form['username'] or not request.form['password']:
               return render_template('login.html', form=form)
           
          username = form.username.data
          password = form.password.data 
          logging.warning('username: [{}] password: [{}]'.format(username,password))
          
          user = mysql_session.query(User).filter_by(name=username).first()

          if user:

               if check_password_hash(user.password, password):
                    token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
                    acesso = Access()
                    acesso.IP = request.environ.get('HTTP_X_REAL_IP', request.remote_addr) 
                    acesso.user_id = user.id
                    acesso.timestamped = datetime.datetime.now()
                    mysql_session.add(acesso)
                    mysql_session.commit()
                    login_user(user)
                    logging.warning('login sucesso')
                    flash('Login com sucesso!')

                    next = request.args.get('next')
                    # is_safe_url should check if the url is safe for redirects.
                    # See http://flask.pocoo.org/snippets/62/ for an example.
                    if not is_safe_url(next):
                         return abort(400)

                    return redirect(next or url_for('index'))

          else:
               flash('Login falhou!')
     g.user = None
     
     return render_template('login.html', form=form)

@app.route('/logout', methods=['GET','POST'])
def logout():
     logout_user()
     return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
     logging.warning('register...')
     form = RegistrationForm(request.form)
     if request.method == 'POST' and form.validate():
          user = User()
          user.public_id = str(uuid.uuid4())
          user.name = form.username.data
          user.email = form.email.data
          user.password = generate_password_hash(form.password.data)
          user.accept_tos = form.accept_tos.data
          user.profile_id = 3 #cliente
          user.created = datetime.datetime.now()
          mysql_session.add(user)
          mysql_session.commit()

          
     
          msg = Message('Usuário cadastrado', sender =   SENDER_MAIL, recipients = [user.email])
          msg.body = "O usuário {} cadastrado pela web em {} informando este email. Para confirmar abra no navegador http://{}:5000{}".format(user.name, user.created, MY_IP, url_for('activation',key=user.public_id))
          mail.send(msg)

          flash('Obrigado pelo cadastro!')
          return redirect(url_for('login'))

     logging.warning('method get')
     return render_template('register.html', form=form)

@app.route('/user-update',methods=['GET','POST'])
def user_update():

     form = UserUpdateForm(request.form)
     user = mysql_session.query(User).filter_by(public_id=current_user.get_id()).first()

     IP = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

     if request.method == 'POST' and form.validate():

          if 'file' not in request.files:
               flash('No file part')
               return redirect(request.url)
          file = request.files['file']
          # If the user does not select a file, the browser submits an
          # empty file without a filename.
          if file.filename == '':
               flash('No selected file')
               return redirect(request.url)
          
          if file and allowed_file(file.filename):
               image_name = user.public_id + '.'+ file.filename.rsplit('.', 1)[1].lower()
               file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_name))
               #user.image = image_name accept_tos
               #mysql_session.query(User).filter(User.public_id == current_user.get_id()).update({'accept_tos': 1})
               
               mysql_session.query(User).filter(User.public_id == current_user.get_id()).update({'image': image_name})
               #mysql_session.execute(update(User, values={image=imagename}))
               #mysql_session.add(user)
               mysql_session.commit()

               

               #return redirect(url_for('user-update.html', name=filename))
               return render_template('user-update.html', form=form, IP=IP)

          

     return render_template('user-update.html', form=form, IP=IP)


@app.route('/profile', methods=['GET','POST'])
def profile():
     form = ProfileForm(request.form)
     profiles = mysql_session.query(Profile)

     if request.method == 'POST' and form.validate():
          profile = Profile()
          profile.name = form.name.data
          profile.description = form.description.data
          mysql_session.add(profile)
          mysql_session.commit()
          flash('Perfil adicionado')
          return redirect(url_for('profile'))


     logging.warning('method get')
     return render_template('profile.html', form=form, profiles=profiles)


@app.route('/profile-edit/<id>', methods=['GET','POST'])
@token_required
def profile_edit(id):

     form = ProfileForm()
     profiles = mysql_session.query(Profile)

     if request.method == 'GET' and id:

          profile = mysql_session.query(Profile).filter_by(id=id).first()

          logging.warning('profile.name: [{}]'.format(profile.name))

          form.name.data = profile.name
          form.description.data = profile.description

          render_template('profile.html', form=form, profiles=profiles)

     if request.method == 'POST' and form.validate:
          form = ProfileForm(request.form)
          mysql_session.add(profile)
          mysql_session.commit()
          return redirect(url_for('profile'))

     return render_template('profile.html', form=form, profiles=profiles)

@app.route('/activation/<key>', methods=['GET'])
def activation(key):
     logging.warning('activation {}'.format(key))
     user = mysql_session.query(User).filter_by(public_id=key).first()
     


     if user:
          user.activated = datetime.datetime.now()
          mysql_session.add(user)
          mysql_session.commit()
          flash('Usuário ativado com sucesso!')
          return redirect(url_for('login'))

     return render_template('index.html')

@app.route('/access')
@login_required
def access():
     acessos = mysql_session.query(func.date(Access.timestamped), Access.IP, User.name, func.count(func.date(Access.timestamped))).outerjoin(User).group_by(func.date(Access.timestamped), Access.IP, User.name).order_by(desc(func.date(Access.timestamped))).all()

     logging.warning(acessos)

     lista_acessos = []
     dias = []

     for acesso in acessos:

          #user = mysql_session.query(User).filter_by(id=acesso.user_id).first()

          a = collections.OrderedDict()
          #a['usuario'] = acesso.name
          a['timestamped'] = acesso[0]
          a['ip'] = acesso[1]
          a['username'] = acesso[2]
          a['count'] = acesso[3]
          lista_acessos.append(a)
          dias.append(acesso[0])
     
     logging.warning('lista: [{}]'.format(lista_acessos)) 

     logging.warning('dias: [{}]'.format(dias))
     
     IP = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
         

     return render_template('access.html',lista_acessos=lista_acessos, IP=IP)

@app.route('/access-graph.png')
@login_required
def access_graph():

     acessos = mysql_session.query(func.date(Access.timestamped), func.count(func.date(Access.timestamped))).group_by(func.date(Access.timestamped), Access.IP).order_by(desc(func.date(Access.timestamped))).all()

     lista_acessos = []
     dias = []
     qtd_acessos = []
     qtd_dias = 0

     for acesso in acessos:

          a = collections.OrderedDict()
          a['timestamped'] = acesso[0]
          a['count'] = acesso[1]
          lista_acessos.append(a)
          dias.append(acesso[0])
          qtd_acessos.append(acesso[1])
          qtd_dias+=1

     ax = plt.subplots(figsize=(9, 3))

     logging.warning('dias: [{}] {}'.format(dias, qtd_dias))

     ind = np.arange(qtd_dias)  

     plt.bar(ind, qtd_acessos, 0.35, yerr=0, label='Acessos')

     plt.axhline(0,color='grey', linewidth=0.8)
     plt.ylabel('Quantidade')
     plt.title('Acessos por dia')
     plt.xticks(ind, labels=dias)
     plt.legend()



     output = io.BytesIO()

     plt.savefig(output)
     
     #FigureCanvas(plt.streamplot()).print_png(output)

     return Response(output.getvalue(), mimetype='image/png')
     
     #return plt.show()
#
#    rest service 
#


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
          our_user = mysql_session.query(User).filter_by(name=user).first()
          logging.warning(our_user.name)

     elif id:
          our_user = mysql_session.query(User).filter_by(id=id_parm).first()
          logging.warning(our_user.name)

     if our_user:
          retorno = jsonify('user:',our_user.name)

     return retorno


@app.route('/service-register', methods=['POST'])
def service_register():
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

     mysql_session.add(user)
     mysql_session.commit()

     return jsonify({'message':'Sucess!'})
     
@app.route('/service-login', methods=['POST'])
def service_login():
     retorno = ''

     auth = request.authorization

     if not auth or not auth.username or not auth.password: 
       return make_response('could not verify', 401, {'Authentication': 'login required"'})   
 
     user = mysql_session.query(User).filter_by(name=auth.username).first()

     logging.warning('user.name: {}'.format(user.name))

     if check_password_hash(user.password, auth.password):
          token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
          acesso = Access()
          acesso.IP = request.environ.get('HTTP_X_REAL_IP', request.remote_addr) 
          acesso.user_id = user.id
          acesso.timestamped = datetime.datetime.now()
          mysql_session.add(acesso)
          mysql_session.commit()

          return jsonify({'token' : token})
 
     return make_response('could not verify',  401, {'Authentication': '"login required"'})



