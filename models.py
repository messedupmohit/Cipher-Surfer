from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    files = db.relationship('SharedFile', backref='owner', lazy=True)

class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # For encryption
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_username = db.Column(db.String(150), nullable=False)  # To whom the file is shared
