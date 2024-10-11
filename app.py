from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from cryptography.fernet import Fernet
import os

# Import the configuration class
from config import Config

# Import the admin blueprint
from admin import create_admin_blueprint

# Initialize Flask app
app = Flask(__name__)

# Apply the configuration from config.py
app.config.from_object(Config)

# Initialize database, migrate, and login manager
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'signin'
login_manager.login_message_category = 'info'

# Register the admin blueprint
create_admin_blueprint(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    profile_picture = db.Column(db.String(100), nullable=True)
    shared_files = db.relationship('SharedFile', backref='recipient', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# SharedFile model
class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(150), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    decryption_key = db.Column(db.String(100), nullable=False)

# Forms
class SignUpForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class SignInForm(FlaskForm):
    email_or_username = StringField('Email or Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class UploadFileForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    recipient_username = StringField('Recipient Username', validators=[DataRequired()])
    submit = SubmitField('Upload')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    profile_picture = FileField('Profile Picture')
    submit = SubmitField('Update Profile')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

# Routes
@app.route('/')
def index():
    return redirect(url_for('signin'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! You can now sign in.', 'success')
        return redirect(url_for('signin'))
    return render_template('signup.html', form=form)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SignInForm()
    if form.validate_on_submit():
        user = User.query.filter((User.email == form.email_or_username.data) | (User.username == form.email_or_username.data)).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Signed in successfully!', 'success')
            return redirect(url_for('home_view'))
        else:
            flash('Login failed. Check email/username and password', 'danger')
    return render_template('signin.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home_view():
    form = UploadFileForm()
    return render_template('home.html', form=form, username=current_user.username, user=current_user)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    form = UploadFileForm()
    if form.validate_on_submit():
        recipient = User.query.filter_by(username=form.recipient_username.data).first()
        if recipient:
            try:
                file = form.file.data
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                file.save(filepath)

                key = Fernet.generate_key()
                cipher_suite = Fernet(key)
                
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                encrypted_data = cipher_suite.encrypt(file_data)
                
                encrypted_filepath = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
                with open(encrypted_filepath, 'wb') as f:
                    f.write(encrypted_data)

                shared_file = SharedFile(filename=filename, file_path=encrypted_filepath, recipient=recipient, decryption_key=key.decode())
                db.session.add(shared_file)
                db.session.commit()

                flash(f'File uploaded and shared securely! The key to decrypt and download it is: "{key.decode()}"\nPlease share this key securely with the recipient.', 'success')

            except Exception as e:
                flash(f'An error occurred: {e}', 'danger')
                app.logger.error(f'Error: {e}')
            return redirect(url_for('home_view'))
        else:
            flash('Recipient username not found.', 'danger')

    return redirect(url_for('home_view'))

@app.route('/decrypt_file/<int:file_id>', methods=['POST'])
@login_required
def decrypt_file(file_id):
    shared_file = SharedFile.query.get_or_404(file_id)
    if shared_file.recipient != current_user:
        flash('You are not authorized to access this file.', 'danger')
        return redirect(url_for('home_view'))

    key = request.form.get('decryption_key')
    if not key:
        flash('Decryption key is required.', 'danger')
        return redirect(url_for('home_view'))

    try:
        cipher_suite = Fernet(key.encode())
        with open(shared_file.file_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)

        decrypted_filepath = os.path.join(app.config['DECRYPTED_FOLDER'], shared_file.filename)
        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)

        return send_from_directory(app.config['DECRYPTED_FOLDER'], shared_file.filename, as_attachment=True)
    except Exception as e:
        flash(f'An error occurred during decryption: {e}', 'danger')
        return redirect(url_for('home_view'))

@app.route('/delete_shared_file/<int:file_id>', methods=['POST'])
@login_required
def delete_shared_file(file_id):
    shared_file = SharedFile.query.get_or_404(file_id)
    
    if shared_file.recipient != current_user:
        flash('You are not authorized to delete this file.', 'danger')
        return redirect(url_for('home_view'))
    
    if os.path.exists(shared_file.file_path):
        os.remove(shared_file.file_path)
    decrypted_file_path = os.path.join(app.config['DECRYPTED_FOLDER'], shared_file.filename)
    if os.path.exists(decrypted_file_path):
        os.remove(decrypted_file_path)

    db.session.delete(shared_file)
    db.session.commit()
    flash('File has been deleted.', 'success')
    return redirect(url_for('home_view'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        if form.profile_picture.data:
            profile_picture = form.profile_picture.data
            filename = secure_filename(profile_picture.filename)
            file_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], filename)

            try:
                # Save the new profile picture
                app.logger.info(f"Saving new profile picture to {file_path}")
                profile_picture.save(file_path)

                # Remove old profile picture if exists
                if current_user.profile_picture:
                    old_file_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], current_user.profile_picture)
                    if os.path.exists(old_file_path):
                        app.logger.info(f"Removing old profile picture at {old_file_path}")
                        os.remove(old_file_path)

                # Update user profile picture filename
                current_user.profile_picture = filename
                db.session.commit()
                flash('Your profile picture has been updated!', 'success')
            except Exception as e:
                flash(f'An error occurred while updating profile picture: {e}', 'danger')
                app.logger.error(f'Error: {e}')
        else:
            flash('No profile picture uploaded.', 'info')

        return redirect(url_for('profile'))

    # Prefill the form with the current user's data
    form.username.data = current_user.username
    form.email.data = current_user.email

    return render_template('profile.html', user=current_user, form=form)

@app.route('/remove_profile_picture', methods=['POST'])
@login_required
def remove_profile_picture():
    if current_user.profile_picture:
        file_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], current_user.profile_picture)
        if os.path.exists(file_path):
            os.remove(file_path)

        current_user.profile_picture = None
        db.session.commit()
        flash('Profile picture removed successfully!', 'success')
    else:
        flash('No profile picture to remove.', 'info')

    return redirect(url_for('profile'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.old_password.data):
            current_user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256', salt_length=8)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('home_view'))
        else:
            flash('Current password is incorrect.', 'danger')
    return render_template('change_password.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('signin'))

@app.route('/shared_files')
@login_required
def shared_files():
    files = SharedFile.query.filter_by(recipient=current_user).all()
    return render_template('shared_files.html', shared_files=files)

# Set the folder for profile pictures and other files
app.config['PROFILE_PICS_FOLDER'] = os.path.join('static', 'uploads', 'profile_pics')
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ENCRYPTED_FOLDER'] = os.path.join('static', 'encrypted_files')
app.config['DECRYPTED_FOLDER'] = os.path.join('static', 'decrypted_files')

if __name__ == '__main__':
    for folder in [app.config['PROFILE_PICS_FOLDER'], app.config['UPLOAD_FOLDER'], app.config['ENCRYPTED_FOLDER'], app.config['DECRYPTED_FOLDER']]:
        if not os.path.exists(folder):
            os.makedirs(folder)
    
    app.run(debug=True)
