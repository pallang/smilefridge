from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_script import Manager, Shell
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from datetime import datetime, timedelta, date
from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import Required, Email, Length, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_mail import Mail, Message
from threading import Thread
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from time import sleep
import os


#변수설정

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY']='hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI'] =\
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['SMARTFRIDGE_MAIL_SUBJECT_PREFIX'] = '[SmartFridge]'
app.config['SMARTFRIDGE_MAIL_SENDER'] = 'SmartFridge Admin <ploki808@gmail.com>'
app.config['SMARTFRIDGE_ADMIN'] = os.environ.get('SMARTFRIDGE_ADMIN')
db = SQLAlchemy(app)
manager = Manager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
password_hash = db.Column(db.String(128))


# 기간끝난 냉장고 사용 종료
def delete_txt():
    while True:
        sleep(86400)
        with open('fridge1.txt') as f1, open('fridge2.txt') as f2:
            lst1_date_ = f1.read().splitlines()
            lst2_date_ = f2.read().splitlines()
            if lst1_date_:
                lst1_date = lst1_date_[2].split('-')
                date_time1 = str(date(int(lst1_date[0]), int(lst1_date[1][1:]), int(lst1_date[2])) - date.today())[:1]
                if date_time1 == '-':
                    with open('fridge1.txt', 'w') as fw1:
                        fw1.write('')
            if lst2_date_:
                lst2_date = lst2_date_[2].split('-')
                date_time2 = str(date(int(lst2_date[0]), int(lst2_date[1][1:]), int(lst2_date[2])) - date.today())[:1]
                if date_time2 == '-':
                    with open('fridge2.txt', 'w') as fw2:
                        fw2.write('')
delete = Thread(target=delete_txt)
delete.start()

def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)
# manager.add_command("shell", Shell(make_context=make_shell_context())

# 메일전송(실행안함)
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['SMARTFRIDGE_MAIL_SUBJECT_PREFIX'] + subject, sender=app.config['SMARTFRIDGE_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    # thr.start()
    return thr


# 권한폼
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name

# 사용자 데이터
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash  = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    @property
    def password(self):
        raise AttributeError('password is not a readalbe attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username

# 로그인폼
class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me loggend in')
    submit = SubmitField('로그인')

# 회원가입폼
class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[Required(), Length(1, 64),
                                                   Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, '
                                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('회원가입')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

# 냉장고데이터폼
class SettingForm(Form):
    time = StringField('Days', validators=[Required(), Length(1,2), Regexp('^[0-9]', 0, 'Only number')])
    pin = StringField('PIN', validators=[Required(), Length(1.64), Regexp('^[0-9]', 0, 'Only number')])
    submit = SubmitField('예약')

# 종료폼
class ShutdownForm(Form):
    submit = SubmitField('지금 사용 종료')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 홈페이지
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', current_time=datetime.utcnow())

# 설명서
@app.route('/explain')
def explain():
    return render_template('explain.html')

# 내정보
@app.route('/user/<name>', methods=['GET','POST'])
@login_required
def user(name):
    with open('fridge1.txt') as f1:
        lst1 = f1.read().splitlines()
        if not lst1:
            usedata='냉장고를 이용하지 않고 있습니다.'
            timelimit=''
            pinnumber=''
        elif lst1[0] == current_user.username:
            usedata = '첫번째 냉장고를 사용 중입니다.'
            timelimit = '사용 종료일은 ' + lst1[2] + '입니다.'
            pinnumber = '설정된 핀번호는 ' + lst1[3] + '입니다.'
            form = ShutdownForm()
            if form.validate_on_submit():
                with open('fridge1.txt', 'w') as f1:
                    f1.write('')
                return render_template('index.html', current_time=datetime.utcnow())
            return render_template('user.html', form=form, name=current_user.username, usedata=usedata, timelimit=timelimit,
                                   pinnumber=pinnumber, username=lst1[0])
    with open('fridge2.txt') as f1:
        lst2 = f1.read().splitlines()
        if not lst2:
            usedata = '냉장고를 이용하지 않고 있습니다.'
            timelimit = ''
            pinnumber = ''
        elif lst2[0] == current_user.username:
            usedata = '두번째 냉장고를 사용 중입니다.'
            timelimit = '사용 종료일은 ' + lst2[2] + '입니다.'
            pinnumber = '설정된 핀번호는 ' + lst2[3] + '입니다.'
            form = ShutdownForm()
            if form.validate_on_submit():
                with open('fridge2.txt', 'w') as f2:
                    f2.write('')
                return render_template('index.html', current_time=datetime.utcnow())
            return render_template('user.html', form=form, name=current_user.username, usedata=usedata,
                                   timelimit=timelimit, pinnumber=pinnumber, username=lst2[0])
    return render_template('user.html', name=current_user.username, usedata=usedata, timelimit=timelimit, pinnumber=pinnumber)

# 회원가입, 로그인, 로그아웃
@app.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        flash('You can now login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# 냉장고1 예약
@app.route('/set1', methods=['GET', 'POST'])
@login_required
def set1():
    with open("fridge1.txt") as fr1:
        lst1 = fr1.read().splitlines()
        if not lst1:
            form = SettingForm()
            if form.validate_on_submit():
                time1 = form.time.data
                pin1 = form.pin.data
                now = date.today()
                delta = timedelta(days=int(time1)-1)
                with open('fridge1.txt', 'w') as fw1:
                    fw1.write(current_user.username + '\n' +
                              '1 \n' +
                              str(now + delta) + '\n' +
                              pin1 + '\n' +
                              current_user.email)
                    return redirect(url_for('index'))
            return render_template('set1.html', form=form)
        elif lst1[0] == current_user.username:
            flash('이 냉장고를 이용하고 있습니다. 내 정보로 가서 확인하세요.')
        elif lst1[1] == '1':
            flash('냉장고가 사용 중입니다. 다른 냉장고를 이용해주세요.')
            return redirect(url_for('index'))
    flash('냉장고가 사용 중입니다. 다른 냉장고를 이용해주세요.')
    return render_template('index.html', current_time=datetime.utcnow())

# 냉장고2 예약
@app.route('/set2', methods=['GET', 'POST'])
@login_required
def set2():
    with open("fridge2.txt") as fr2:
        lst2 = fr2.read().splitlines()
        if not lst2:
            form = SettingForm()
            if form.validate_on_submit():
                time2 = form.time.data
                pin2 = form.pin.data
                now = date.today()
                delta = timedelta(days=int(time2)-1)
                with open('fridge2.txt', 'w') as fw2:
                    fw2.write(current_user.username + '\n' +
                              '1 \n' +
                              str(now + delta) + '\n' +
                              pin2 + '\n' +
                              current_user.email)
                    return redirect(url_for('index'))
            return render_template('set2.html', form=form)
        elif lst2[0] == current_user.username:
            flash('이 냉장고를 이용하고 있습니다. 내 정보로 가서 확인하세요.')
        elif lst2[1] == '1':
            flash('냉장고가 사용 중입니다. 다른 냉장고를 이용해주세요.')
            return redirect(url_for('index'))
    flash('냉장고가 사용 중입니다. 다른 냉장고를 이용해주세요.')
    return render_template('index.html', current_time=datetime.utcnow())

# Errorhandler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# 실행
if __name__ == '__main__':
    app.run(host='1.233.239.66', port='80', debug=True)
    # manager.run()
    # db.drop_all()
    # db.create_all()