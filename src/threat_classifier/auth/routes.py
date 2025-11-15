from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort, send_file, current_app
from flask_login import login_required, current_user, logout_user
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from src.threat_classifier.auth.auth_manager import AuthManager
from src.threat_classifier.database.connection import db
from src.threat_classifier.database.models import User, Role, PasswordResetToken
from io import BytesIO

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        success, message = AuthManager.login(username, password, remember)
        
        if success:
            if message == "2FA":
                # Redirect to 2FA verification page
                return redirect(url_for('auth.verify_2fa'))
            else:
                flash('Login successful!', 'success')
                # Redirect to the page user wanted to access or to home
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
        else:
            flash(message, 'danger')
    
    return render_template('auth/login.html')

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Check if there's a pending 2FA verification
    if 'pending_user_id' not in session:
        flash('No pending login requiring 2FA verification', 'warning')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        token = request.form.get('token')
        
        success, message = AuthManager.verify_2fa(token)
        
        if success:
            flash('Login successful!', 'success')
            # Redirect to the page user wanted to access or to home
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash(message, 'danger')
    
    return render_template('auth/verify_2fa.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        
        # Validate form data
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html')
        
        # Register user
        success, message = AuthManager.register_user(
            username, email, password, first_name, last_name
        )
        
        if success:
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
    
    return render_template('auth/register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    # If user is admin, get users and roles for user management
    users = None
    all_roles = None
    
    if AuthManager.is_admin(current_user):
        users = AuthManager.get_all_users()
        
        # Get all roles for the edit modal
        db_session = db.get_session()
        try:
            all_roles = db_session.query(Role).all()
        finally:
            db_session.close()
    
    return render_template('auth/profile.html', users=users, all_roles=all_roles)

@auth_bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    
    data = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email
    }
    
    success, message = AuthManager.update_user(current_user.id, data)
    
    if success:
        flash('Profile updated successfully', 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        token = request.form.get('token')
        
        # Verify the token matches the secret
        import pyotp
        totp = pyotp.TOTP(session.get('temp_2fa_secret'))
        
        if totp.verify(token):
            # Save the secret to the user's account
            db_session = db.get_session()
            try:
                user = db_session.query(User).get(current_user.id)
                user.totp_secret = session.get('temp_2fa_secret')
                db_session.commit()
                
                # Clear the temporary secret
                session.pop('temp_2fa_secret', None)
                
                flash('Two-factor authentication has been enabled for your account.', 'success')
                return redirect(url_for('auth.profile'))
            except Exception as e:
                flash(f'Error enabling 2FA: {str(e)}', 'danger')
            finally:
                db_session.close()
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    # Generate a new secret and QR code
    success, message, qr_code = AuthManager.setup_2fa(current_user.id)
    
    if not success:
        flash(message, 'danger')
        return redirect(url_for('auth.profile'))
    
    # Store the secret temporarily in the session
    db_session = db.get_session()
    try:
        user = db_session.query(User).get(current_user.id)
        session['temp_2fa_secret'] = user.totp_secret
        # Reset the secret in the database until verified
        user.totp_secret = None
        db_session.commit()
    finally:
        db_session.close()
    
    return render_template('auth/setup_2fa.html', qr_code=qr_code, secret_key=session.get('temp_2fa_secret'))

@auth_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    password = request.form.get('password')
    
    success, message = AuthManager.disable_2fa(current_user.id, password)
    
    if success:
        flash('Two-factor authentication has been disabled.', 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('auth.profile'))
    
    success, message = AuthManager.change_password(
        current_user.id, current_password, new_password
    )
    
    if success:
        flash('Password changed successfully', 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('auth.profile'))

# Admin routes
@auth_bp.route('/admin/users')
@login_required
def admin_users():
    if not AuthManager.is_admin(current_user):
        abort(403)
    
    users = AuthManager.get_all_users()
    
    # Get all roles for the edit modal
    db_session = db.get_session()
    try:
        all_roles = db_session.query(Role).all()
    finally:
        db_session.close()
    
    return render_template('auth/admin_users.html', users=users, all_roles=all_roles)

@auth_bp.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if not AuthManager.is_admin(current_user):
        abort(403)
    
    user = AuthManager.get_user(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('auth.profile'))
    
    if request.method == 'POST':
        # Handle role updates
        selected_roles = request.form.getlist('roles')
        
        db_session = db.get_session()
        try:
            user_obj = db_session.query(User).get(user_id)
            if user_obj:
                # Update basic user info
                user_obj.email = request.form.get('email')
                user_obj.first_name = request.form.get('first_name')
                user_obj.last_name = request.form.get('last_name')
                
                # Update roles
                user_obj.roles.clear()
                for role_name in selected_roles:
                    role = db_session.query(Role).filter_by(name=role_name).first()
                    if role:
                        user_obj.roles.append(role)
                
                db_session.commit()
                flash('User updated successfully', 'success')
            else:
                flash('User not found', 'danger')
        except Exception as e:
            db_session.rollback()
            flash(f'Error updating user: {str(e)}', 'danger')
        finally:
            db_session.close()
        
        return redirect(url_for('auth.profile'))
    
    return render_template('auth/admin_edit_user.html', user=user)

@auth_bp.route('/admin/user/<int:user_id>/reset-password', methods=['POST'])
@login_required
def admin_reset_password(user_id):
    if not AuthManager.is_admin(current_user):
        abort(403)
    
    new_password = request.form.get('new_password')
    
    db_session = db.get_session()
    try:
        user = db_session.query(User).get(user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('auth.profile'))
        
        user.set_password(new_password)
        db_session.commit()
        
        flash('Password reset successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error resetting password: {str(e)}', 'danger')
    finally:
        db_session.close()
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/admin/add-user', methods=['POST'])
@login_required
def admin_add_user():
    # Check if user is admin
    if not current_user.has_role('admin'):
        abort(403)
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    role = request.form.get('role')
    
    # Validate form data
    if not username or not email or not password:
        flash('All fields are required', 'danger')
        return redirect(url_for('auth.profile'))
    
    # Register user with specified role
    success, message = AuthManager.register_user(
        username, email, password, first_name, last_name, role
    )
    
    if success:
        flash(f'User {username} created successfully with {role} role!', 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not AuthManager.is_admin(current_user):
        abort(403)
    
    # Prevent admin from deleting themselves
    if user_id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('auth.profile'))
    
    db_session = db.get_session()
    try:
        user = db_session.query(User).get(user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('auth.profile'))
        
        username = user.username
        db_session.delete(user)
        db_session.commit()
        
        flash(f'User {username} deleted successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    finally:
        db_session.close()
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        
        db_session = db.get_session()
        try:
            user = db_session.query(User).filter_by(email=email).first()
            
            if user:
                # Create password reset token
                reset_token = PasswordResetToken(user_id=user.id)
                db_session.add(reset_token)
                db_session.commit()
                
                # Send reset email
                try:
                    from app import mail
                    reset_url = url_for('auth.reset_password', token=reset_token.token, _external=True)
                    
                    msg = Message(
                        subject='Password Reset Request - Network Threat Classifier',
                        recipients=[user.email],
                        sender=current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@networkthreatclassifier.com')
                    )
                    
                    msg.html = f"""
                    <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                            <h2 style="color: #3b82f6;">Password Reset Request</h2>
                            <p>Hello {user.first_name or user.username},</p>
                            <p>You have requested to reset your password for your Network Threat Classifier account.</p>
                            <p>Click the button below to reset your password:</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{reset_url}" 
                                   style="background-color: #3b82f6; color: white; padding: 12px 24px; 
                                          text-decoration: none; border-radius: 5px; display: inline-block;">
                                    Reset Password
                                </a>
                            </div>
                            <p>Or copy and paste this link into your browser:</p>
                            <p style="word-break: break-all; background-color: #f5f5f5; padding: 10px; border-radius: 5px;">
                                {reset_url}
                            </p>
                            <p><strong>This link will expire in 24 hours.</strong></p>
                            <p>If you did not request this password reset, please ignore this email.</p>
                            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                            <p style="font-size: 12px; color: #666;">
                                This is an automated message from Network Threat Classifier. Please do not reply to this email.
                            </p>
                        </div>
                    </body>
                    </html>
                    """
                    
                    mail.send(msg)
                    flash('Password reset instructions have been sent to your email address.', 'success')
                    
                except Exception as e:
                    flash('Error sending email. Please try again later.', 'danger')
                    print(f"Email send error: {e}")
            else:
                # Don't reveal if email exists or not for security
                flash('If an account with that email exists, password reset instructions have been sent.', 'info')
                
        except Exception as e:
            db_session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            print(f"Forgot password error: {e}")
        finally:
            db_session.close()
            
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    db_session = db.get_session()
    try:
        reset_token = db_session.query(PasswordResetToken).filter_by(token=token).first()
        
        if not reset_token or not reset_token.is_valid():
            flash('Invalid or expired password reset link.', 'danger')
            return redirect(url_for('auth.forgot_password'))
        
        if request.method == 'POST':
            new_password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if new_password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('auth/reset_password.html', token=token)
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return render_template('auth/reset_password.html', token=token)
            
            # Update user password
            user = db_session.query(User).get(reset_token.user_id)
            user.set_password(new_password)
            
            # Mark token as used
            reset_token.mark_as_used()
            
            db_session.commit()
            
            flash('Your password has been reset successfully. You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        
        return render_template('auth/reset_password.html', token=token)
        
    except Exception as e:
        db_session.rollback()
        flash('An error occurred. Please try again.', 'danger')
        print(f"Reset password error: {e}")
        return redirect(url_for('auth.forgot_password'))
    finally:
        db_session.close()

@auth_bp.route('/unauthorized')
def unauthorized():
    return render_template('auth/unauthorized.html')