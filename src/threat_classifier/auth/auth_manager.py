import os
import pyotp
import qrcode
from io import BytesIO
from datetime import datetime
from flask import current_app, session, flash, redirect, url_for, request
from flask_login import LoginManager, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from src.threat_classifier.database.connection import db
from src.threat_classifier.database.models import User, Role

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    from sqlalchemy.orm import joinedload
    db_session = db.get_session()
    try:
        user = db_session.query(User).options(joinedload(User.roles)).filter(User.id == int(user_id)).first()
        if user:
            # Expunge the user from the session to avoid DetachedInstanceError
            db_session.expunge(user)
        return user
    finally:
        db_session.close()

class AuthManager:
    @staticmethod
    def register_user(username, email, password, first_name=None, last_name=None, role=None):
        """Register a new user"""
        db_session = db.get_session()
        try:
            # Check if user already exists
            existing_user = db_session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                if existing_user.username == username:
                    return False, "Username already exists"
                else:
                    return False, "Email already exists"
            
            # Check if this is the first user BEFORE creating the new user
            user_count = db_session.query(User).count()
            is_first_user = user_count == 0
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                created_at=datetime.utcnow()
            )
            new_user.set_password(password)
            
            # Add user to database
            db_session.add(new_user)
            
            # Assign role
            if role:
                # Use specified role
                target_role = db_session.query(Role).filter_by(name=role).first()
                if not target_role:
                    target_role = Role(name=role, description=f'{role.capitalize()} Role')
                    db_session.add(target_role)
                new_user.roles.append(target_role)
            else:
                # Make the first user admin, all others regular users
                if is_first_user:
                    admin_role = db_session.query(Role).filter_by(name='admin').first()
                    if not admin_role:
                        admin_role = Role(name='admin', description='Administrator')
                        db_session.add(admin_role)
                    new_user.roles.append(admin_role)
                else:
                    user_role = db_session.query(Role).filter_by(name='user').first()
                    if not user_role:
                        user_role = Role(name='user', description='Regular User')
                        db_session.add(user_role)
                    new_user.roles.append(user_role)
            
            db_session.commit()
            return True, "User registered successfully"
        except Exception as e:
            db_session.rollback()
            return False, f"Registration error: {str(e)}"
        finally:
            db_session.close()
    
    @staticmethod
    def login(username, password, remember=False):
        """Login a user"""
        db_session = db.get_session()
        try:
            user = db_session.query(User).filter_by(username=username).first()
            
            if not user or not user.check_password(password):
                return False, "Invalid username or password"
            
            if not user.is_active:
                return False, "Account is disabled"
            
            # Check if 2FA is enabled
            if user.totp_secret:
                # Store user ID in session for 2FA verification
                session['pending_user_id'] = user.id
                return True, "2FA"
            
            # Update last login time
            user.last_login = datetime.utcnow()
            db_session.commit()
            
            # Log in the user
            login_user(user, remember=remember)
            
            # Set initial session activity timestamp
            session['last_activity'] = datetime.now().isoformat()
            session.permanent = True
            
            return True, "Login successful"
        except Exception as e:
            return False, f"Login error: {str(e)}"
        finally:
            db_session.close()
    
    @staticmethod
    def verify_2fa(token):
        """Verify 2FA token"""
        if 'pending_user_id' not in session:
            return False, "No pending login"
        
        db_session = db.get_session()
        try:
            user_id = session['pending_user_id']
            user = db_session.query(User).get(user_id)
            
            if not user or not user.totp_secret:
                return False, "Invalid user or 2FA not set up"
            
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(token):
                # Update last login time
                user.last_login = datetime.utcnow()
                db_session.commit()
                
                # Log in the user
                login_user(user)
                
                # Set initial session activity timestamp
                session['last_activity'] = datetime.now().isoformat()
                session.permanent = True
                
                # Clear pending user ID
                session.pop('pending_user_id', None)
                return True, "2FA verification successful"
            else:
                return False, "Invalid 2FA token"
        except Exception as e:
            return False, f"2FA verification error: {str(e)}"
        finally:
            db_session.close()
    
    @staticmethod
    def setup_2fa(user_id):
        """Set up 2FA for a user"""
        db_session = db.get_session()
        try:
            user = db_session.query(User).get(user_id)
            if not user:
                return False, "User not found", None
            
            # Generate TOTP secret
            secret = user.generate_totp_secret()
            db_session.commit()
            
            # Generate QR code
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(user.email, issuer_name="Network Threat Classifier")
            
            img = qrcode.make(uri)
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            
            # Convert to base64 for HTML display
            import base64
            qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            return True, "2FA setup successful", qr_code
        except Exception as e:
            db_session.rollback()
            return False, f"2FA setup error: {str(e)}", None
        finally:
            db_session.close()
    
    @staticmethod
    def disable_2fa(user_id, password):
        """Disable 2FA for a user"""
        db_session = db.get_session()
        try:
            user = db_session.query(User).get(user_id)
            if not user:
                return False, "User not found"
            
            if not user.check_password(password):
                return False, "Invalid password"
            
            user.totp_secret = None
            db_session.commit()
            
            return True, "2FA disabled successfully"
        except Exception as e:
            db_session.rollback()
            return False, f"Error disabling 2FA: {str(e)}"
        finally:
            db_session.close()
    
    @staticmethod
    def get_all_users():
        """Get all users (for admin)"""
        from sqlalchemy.orm import joinedload
        db_session = db.get_session()
        try:
            users = db_session.query(User).options(joinedload(User.roles)).all()
            # Expunge users from session to avoid DetachedInstanceError
            for user in users:
                db_session.expunge(user)
            return users
        finally:
            db_session.close()
    
    @staticmethod
    def get_user(user_id):
        """Get user by ID"""
        from sqlalchemy.orm import joinedload
        db_session = db.get_session()
        try:
            user = db_session.query(User).options(joinedload(User.roles)).filter(User.id == user_id).first()
            if user:
                db_session.expunge(user)
            return user
        finally:
            db_session.close()
    
    @staticmethod
    def update_user(user_id, data):
        """Update user information"""
        db_session = db.get_session()
        try:
            user = db_session.query(User).get(user_id)
            if not user:
                return False, "User not found"
            
            # Update fields
            if 'email' in data:
                user.email = data['email']
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'is_active' in data:
                user.is_active = data['is_active']
            
            db_session.commit()
            return True, "User updated successfully"
        except Exception as e:
            db_session.rollback()
            return False, f"Error updating user: {str(e)}"
        finally:
            db_session.close()
    
    @staticmethod
    def change_password(user_id, current_password, new_password):
        """Change user password"""
        db_session = db.get_session()
        try:
            user = db_session.query(User).get(user_id)
            if not user:
                return False, "User not found"
            
            if not user.check_password(current_password):
                return False, "Current password is incorrect"
            
            user.set_password(new_password)
            db_session.commit()
            
            return True, "Password changed successfully"
        except Exception as e:
            db_session.rollback()
            return False, f"Error changing password: {str(e)}"
        finally:
            db_session.close()
    
    @staticmethod
    def has_role(user, role_name):
        """Check if user has a specific role"""
        if not user or not user.roles:
            return False
        
        return any(role.name == role_name for role in user.roles)
    
    @staticmethod
    def is_admin(user):
        """Check if user is an admin"""
        return AuthManager.has_role(user, 'admin')