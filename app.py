from flask import Flask, render_template, url_for, redirect, session, flash
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_user import roles_required, UserManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# user_manager = UserManager()
# user_manager.init_app(app, db, UserClass='User')
#
#
# @user_manager
# def user_manager():
#     return ''


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------- DB Classes Tables Config ----------------------------


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    roles = db.relationship('Role', secondary='user_roles',
                            backref=db.backref('users', lazy='dynamic'))


# Define Role model
class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)


# Define UserRoles model
class UserRoles(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))


class Tokens(db.Model):
    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    key = db.Column(db.String(50))

    def __init__(self, name, key):
        self.name = name
        self.key = key


# ---------------------- DB Classes Tables Config - END ----------------------------


def validate_username(username):
    existing_user_username = User.query.filter_by(
        username=username.data).first()
    if existing_user_username:
        raise ValidationError(
            'That username already exists. Please choose a different one.')


# ---------------------- Flask Form Config ----------------------------


class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=100)], render_kw={"class": "username", "placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=100)], render_kw={"class": "username", "placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class ResetPasswordForm(FlaskForm):
    # Drop down to grab list of users
    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Reset Password')


class AddToken(FlaskForm):
    platform = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Platform Name"})

    key = StringField(validators=[
        InputRequired(), Length(min=8, max=50)], render_kw={"placeholder": "Key"})

    submit = SubmitField('Add')


class ModifyToken(FlaskForm):
    # Dropdown of Token to be updated
    key = StringField(validators=[
        InputRequired(), Length(min=8, max=50)], render_kw={"placeholder": "Key"})

    submit = SubmitField('Update')


# ---------------------- Flask Form Config - END ----------------------------


@app.route('/')  # ----- Splash Page ------
def home():
    title = 'Panasonic 2FA'
    return render_template('home.html', title=title)


@app.route('/login', methods=['GET', 'POST'])  # ----- Login Page ------
def login():
    title = 'Panasonic | Login',
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['user_name'] = form.username.data
                return redirect(url_for('tokens'))
    return render_template('login.html', form=form, title=title)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('User successfully logged out.')
    return redirect(url_for('home'))


@app.route('/tokens', methods=['GET', 'POST'])  # ----- List All Tokens ------
@login_required
def tokens():
    title = 'Panasonic | 2FA Tokens'
    return render_template('test.html', title=title)


# ---------------------- Admin Permission Pages ----------------------------
@app.route('/admin/dashboard')  # ----- Dashboard Main Page ------
# @roles_required('admin')
def admin_dashboard():
    title = 'Panasonic | Admin Dashboard'
    # render the admin dashboard
    return render_template('2fa-admin/dashboard.html', title=title)


@app.route('/admin/tokens/modify', methods=['GET', 'POST'])  # ----- Modify Token ------
@login_required
# @roles_required('admin')
def modify_token():
    title = 'Panasonic | Modify - 2FA Tokens'
    form = ModifyToken()
    if form.validate_on_submit():
        update_token = Tokens(name=form.platform.data, key=form.key.data)
        db.session.add(update_token)
        db.session.commit()
        return redirect(url_for('tokens'))
    return render_template('2fa-admin/modify-2fa.html', title=title, form=form)


@app.route('/admin/tokens/add', methods=['GET', 'POST'])  # ----- Add Token ------
@login_required
# @roles_required('admin')
def add_token():
    title = 'Panasonic | Add - 2FA Tokens'
    form = AddToken()
    if form.validate_on_submit():
        new_token = Tokens(name=form.platform.data, key=form.key.data)
        db.session.add(new_token)
        db.session.commit()
        return redirect(url_for('tokens'))
    return render_template('2fa-admin/add-2fa.html', title=title, form=form)


@app.route('/admin/register', methods=['GET', 'POST'])
# @roles_required('admin')
def register():
    title = 'Panasonic | Create User'
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('2fa-admin/register.html', form=form, title=title)


@app.route('/admin/reset-password', methods=['GET', 'POST'])
# @roles_required('admin')
def reset_password():
    title = 'Panasonic | Reset Password'
    form = ResetPasswordForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        update_pwd = User(password=hashed_password)
        db.session.add(update_pwd)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('2fa-admin/reset-password.html', form=form, title=title)


if __name__ == "__main__":
    app.run(debug=True)
