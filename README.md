# Cipher Surfer

Cipher Surfer is a web application built with Flask that allows users to securely upload, share, and download files. The platform provides secure file sharing with encryption using the **Fernet** encryption scheme and ensures that files are accessible only by authorized users.

## Features

- **User Authentication**: Sign up, log in, and password management functionality for users.
- **Secure File Upload**: Users can upload files that are encrypted before being stored.
- **Decryption on Download**: Files are decrypted using a key when a recipient downloads them.
- **Profile Management**: Users can update their profile, change passwords, and manage profile pictures.
- **Admin Panel**: Admins can access user data including usernames and emails through a separate interface.
- **File Sharing**: Share encrypted files with other users by specifying their username.

## Technologies Used

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS (via Flask templates)
- **Database**: SQLAlchemy (SQLite by default)
- **Encryption**: Fernet (from `cryptography` package)
- **User Authentication**: Flask-Login
- **File Storage**: Secure handling and encryption of files using `werkzeug` and `cryptography`
- **Blueprints**: Organized routes and admin access using Flask Blueprints

## Setup

### Prerequisites

- Python 3.x installed
- `pip` (Python package manager)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/messedupmohit/Cipher-Surfer.git
   ```
   
2. **Navigate to the project directory**:
   ```bash
   cd Cipher-Surfer
   ```

3. **Create a virtual environment** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # For Linux/Mac
   # or
   venv\Scripts\activate  # For Windows
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Set up the database**:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

6. **Run the app**:
   ```bash
   flask run
   ```

   The app will be available at `http://127.0.0.1:5000`.

### Configuration

Before running the app, ensure that the configuration values in the `config.py` file are correctly set:

- `SECRET_KEY`: Replace with a securely generated key for session management.
- `SQLALCHEMY_DATABASE_URI`: Update the URI if you are using a different database system.

### File Upload Configuration

Ensure the following directories exist in your project for handling file uploads and encryption:

- `static/uploads`
- `static/encrypted_files`
- `static/decrypted_files`
- `static/uploads/profile_pics`

The app will create these directories if they don’t exist when run.

## Usage

1. **Sign Up**: Register an account to start uploading files.
2. **Upload File**: Upload files and securely share them with other users by entering their username.
3. **File Decryption**: Recipients can download and decrypt files by providing the correct decryption key.
4. **Admin Access**: Admins can view a separate admin panel to manage user details.

## Admin Panel

A separate admin interface allows authorized users to access sensitive data like user emails and usernames. The `admin.py` and associated files provide the blueprint for this feature.

## Future Enhancements

- Implement multi-user file sharing
- Add role-based access control for users
- Enhance the UI with additional styling and front-end frameworks
- Add support for more file encryption algorithms
- Work on Admin panel as it is not functional as of now

