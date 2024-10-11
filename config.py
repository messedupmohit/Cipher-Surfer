import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Consider using a more secure random key in production
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    ENCRYPTED_FOLDER = 'encrypted_files'
    DECRYPTED_FOLDER = 'decrypted_files'
    PROFILE_PICS_FOLDER = 'profile_pics'  # Added folder for profile pictures
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limit upload size to 16MB (adjust as needed)
