from app import app
from flask import jsonify, request, make_response, render_template, redirect, flash, session, url_for, g
from flask_mail import Message
from werkzeug.security import generate_password_hash,check_password_hash
from app.models.profile import Profile
from config import MY_IP, mysql_session
import logging
from functools import wraps
import jwt
import datetime
import uuid

from app.models.user import User
from app.models.access import Access
from app.forms import RegistrationForm, ProfileForm
from app import mail



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
@app.route('/index')
def index():
     if session:

          if session['public_id']:
               current_user = mysql_session.query(User).filter_by(public_id=session['public_id']).first()
          
               return render_template('index.html', user=current_user)
          
     return render_template('index.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
     if request.method == 'POST':

          if not request.form['username'] or not request.form['password']:
               return render_template('login.html')
           
          username = request.form['username']
          password = request.form['password']
          logging.warning('password: {}'.format(password))
          user = mysql_session.query(User).filter_by(name=username).first()

          if user:

               if check_password_hash(user.password, password):
                    acesso = Access()
                    acesso.IP = request.environ.get('HTTP_X_REAL_IP', request.remote_addr) 
                    acesso.user_id = user.id
                    acesso.timestamped = datetime.datetime.now()
                    mysql_session.add(acesso)
                    mysql_session.commit()
                    session.clear()
                    session['public_id'] = user.public_id
                    g.user = user
                    logging.warning('login sucesso')
                    flash('Login com sucesso!')

                    return redirect(url_for('index'))
          else:
               flash('Login falhou!')
     g.user = None
     
     return render_template('login.html')

@app.route('/logout', methods=['GET','POST'])
def logout():
     session.clear()
     return redirect(url_for('index'))

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



