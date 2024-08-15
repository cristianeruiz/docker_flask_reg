# project/user/views.py


#################
#### imports ####
#################
import datetime

from flask import render_template, Blueprint, url_for, \
    redirect, flash, request
from flask_login import login_user, logout_user, \
    login_required, current_user

from project.models import User
# from project.email import send_email
from project import db, bcrypt
from .forms import LoginForm, RegisterForm, ChangePasswordForm, ForgotPasswordForm
from project.token import generate_confirmation_token, confirm_token
from project.email import send_email
from project.decorators import check_confirmed
from flask_jwt_extended import create_access_token, decode_token
from project.services.mail_service import send_email
from project import app

from project.resources.errors import SchemaValidationError, InternalServerError, \
    EmailDoesnotExistsError, BadTokenError
from jwt.exceptions import ExpiredSignatureError, DecodeError, \
    InvalidTokenError

################
#### config ####
################

user_blueprint = Blueprint('user', __name__,)


################
#### routes ####
################

@user_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        user = User(
            email=form.email.data,
            password=form.password.data,
            confirmed=False
        )
        db.session.add(user)
        db.session.commit()

        token = generate_confirmation_token(user.email)
        confirm_url = url_for('user.confirm_email', token=token, _external=True)
        html = render_template('user/activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"

        url = request.host_url + 'reset/'
        #send_email(user.email, subject, html)
        send_email('['+app.config['APP_NAME']+'] '+subject,
                        sender=app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[user.email],
                        text_body=render_template('email/reset_password.txt',
                                                url=url),
                        html_body=html)

        login_user(user)

        flash('A confirmation email has been sent via email.', 'success')
        return redirect(url_for("user.unconfirmed"))

    return render_template('user/register.html', form=form)

@user_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(
                user.password, request.form['password']):
            login_user(user)
            flash('Welcome.', 'success')
            return redirect(url_for('main.home'))
        else:
            flash('Invalid email and/or password.', 'danger')
            return render_template('user/login.html', form=form)
    return render_template('user/login.html', form=form)


@user_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You were logged out.', 'success')
    return redirect(url_for('user.login'))


@user_blueprint.route('/profile', methods=['GET', 'POST'])
@login_required
@check_confirmed
def profile():
    form = ChangePasswordForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=current_user.email).first()
        if user:
            user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            db.session.commit()
            flash('Password successfully changed.', 'success')
            return redirect(url_for('user.profile'))
        else:
            flash('Password change was unsuccessful.', 'danger')
            return redirect(url_for('user.profile'))
    return render_template('user/profile.html', form=form)


@user_blueprint.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('main.home'))


@user_blueprint.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect('main.home')
    flash('Please confirm your account!', 'warning')
    return render_template('user/unconfirmed.html')


@user_blueprint.route('/resend')
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('user.confirm_email', token=token, _external=True)
    html = render_template('user/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    #send_email(current_user.email, subject, html)
    send_email('['+app.config['APP_NAME']+'] Resend Confirmation',
                        sender=app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[current_user.email],
                        text_body=render_template('email/reset_password.txt',
                                                url=confirm_url),
                        html_body=html)

    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('user.unconfirmed'))


@user_blueprint.route('/forgot', methods=['GET', 'POST'])
def forgot_password():

    #token = generate_confirmation_token(current_user.email)
    #confirm_url = url_for('user.confirm_email', token=token, _external=True)
    #html = render_template('user/activate.html', confirm_url=confirm_url)
    #subject = "Please confirm your email"

    form = ForgotPasswordForm(request.form)
    if form.validate_on_submit():
        
        url = request.host_url + 'reset/'
        try:
            
            email = form.email
            
            user = User.query.filter_by(email=email.data,confirmed=True).first()
            
            expires = datetime.timedelta(hours=24)
            reset_token = create_access_token(identity=str(user.id), expires_delta=expires)

            send_email('['+app.config['APP_NAME']+'] Reset Your Password',
                        sender=app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[user.email],
                        text_body=render_template('email/reset_password.txt',
                                                url=url + reset_token),
                        html_body=render_template('email/reset_password.html',
                                                url=url + reset_token))
            
        except SchemaValidationError as e:
            flash(str(e), 'danger')
            return redirect(url_for("user.login"))
        except EmailDoesnotExistsError as e:
            flash(str(e), 'danger')
            return redirect(url_for("user.login"))
        except Exception as e:
            flash(str(e), 'danger')
            return redirect(url_for("user.login"))

        flash('An email to Reset Your Password has been sent.', 'success')
        return redirect(url_for("user.login"))


    return render_template('user/forgot_password.html', form=form)


@user_blueprint.route('/reset/<reset_token>', methods=['GET', 'POST'])
def reset_password(reset_token):

    url = request.host_url + 'reset/'
    try:

        if not reset_token:
            raise SchemaValidationError

        #user_id = decode_token(reset_token)['identity']
        user_id = decode_token(reset_token)['sub']

        #user = User.objects.get(id=user_id)

        #user.modify(password=password)
        #user.hash_password()
        #user.save()

        form = ChangePasswordForm(request.form)
        if form.validate_on_submit():
            
            user = User.query.filter_by(id=user_id, confirmed=True).first()
            if user:
                user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                db.session.commit()
                flash('Password successfully changed.', 'success')
                send_email('['+app.config['APP_NAME']+'] Reset Your Password',
                        sender=app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[user.email],
                            text_body='Password reset was successful',
                            html_body='<p>Password reset was successful</p>')
            else:
                flash('Password change was unsuccessful.', 'danger')
                
            return redirect(url_for("user.login"))
        return render_template('user/reset_password.html', form=form)

    except SchemaValidationError as e:
        flash(str(e), 'danger')
        return redirect(url_for("user.login"))
    except ExpiredSignatureError as e:
        flash(str(e), 'danger')
        return redirect(url_for("user.login"))
    except (DecodeError, InvalidTokenError) as exc:
        flash(str(exc), 'danger')
        return redirect(url_for("user.login"))
    except Exception as e:
        flash(str(e), 'danger')
        return redirect(url_for("user.login"))
        

"""
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('user.confirm_email', token=token, _external=True)
    html = render_template('user/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('user.unconfirmed'))
"""