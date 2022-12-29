from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Prisijungimas pavyko!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Neteisingai ivestas slaptazodis, bandykite dar karta.', category='error')
        else:
            flash('Tokio el. pasto nera, uzsiregistruokite.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Toks el. pastas jau yra.', category='error')
        elif len(email) < 4:
            flash('El. pasta turi buti ne trumpesnis nei 3 simboliai.', category='error')
        elif len(first_name) < 2:
            flash('Vardas turi buti ne trumpesnis nei 1 simbolis.', category='error')
        elif password1 != password2:
            flash('Slaptazodziai nesutampa.', category='error')
        elif len(password1) < 7:
            flash('Slaptazodi turi sudaryti bent 7 simboliai.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Vartotojas sukurtas!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
