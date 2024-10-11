from flask import Blueprint, render_template, request, current_app
from models import User, db

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/users')
def list_users():
    users = User.query.all()  # Fetch all users
    return render_template('admin_users.html', users=users)

@admin_bp.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)  # Get user by ID
    return render_template('admin_user_profile.html', user=user)

# Initialize Blueprint in a separate function
def create_admin_blueprint(app):
    app.register_blueprint(admin_bp)
