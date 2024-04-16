from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:yourpassword@10.100.3.29/BokBibliotekDB'
app.config['SECRET_KEY'] = 'superduperhemmelig'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'studenter'
    id = db.Column('StudentID', db.Integer, primary_key=True)
    fornavn = db.Column('Fornavn', db.String(100), nullable=False)
    etternavn = db.Column('Etternavn', db.String(100), nullable=False)
    email = db.Column('Email', db.String(100), unique=True, nullable=False)
    password_hash = db.Column('password_hash', db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fornavn = request.form['fornavn']
        etternavn = request.form['etternavn']
        email = request.form['email']
        password = request.form['password']

        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            flash('E-postadressen er allerede i bruk.')
            return redirect(url_for('register'))

        new_user = User(fornavn=fornavn, etternavn=etternavn, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registreringen var vellykket. Du kan nå logge inn.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('profile'))
        else:
            flash('Feil brukernavn eller passord.')
    return render_template('login.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', fornavn=current_user.fornavn, etternavn=current_user.etternavn)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
