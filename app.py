from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
from models import db, User, Challenge, Submission, UserSession
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
from datetime import datetime
import os
import logging

# Production configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'technovaganza-ctf-secret-2025')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Use SQLite for development (no compilation needed)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ctf.db'
    
    # Database configuration for Render
    if os.environ.get('DATABASE_URL'):
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   logger=True,
                   engineio_logger=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Enhanced Admin decorator with logging and security
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            logger.warning(f"Unauthorized access attempt to admin panel from IP: {request.remote_addr}")
            return redirect(url_for('login'))
        
        if not current_user.is_admin:
            logger.warning(f"Non-admin user '{current_user.username}' attempted to access admin panel from IP: {request.remote_addr}")
            return render_template('unauthorized.html'), 403
        
        # Log admin access for security monitoring
        logger.info(f"Admin user '{current_user.username}' accessed {request.path} from IP: {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function

def calculate_points(challenge_id, user_id):
    """
    Calculate points based on solving order:
    - 1st solver: 100% points
    - 2nd solver: 90% points  
    - 3rd solver: 80% points
    - 4th+ solver: 50% points (minimum)
    """
    # Count how many teams have already solved this challenge (EXCLUDING current user)
    solved_count = Submission.query.filter_by(
        challenge_id=challenge_id,
        is_correct=True
    ).filter(Submission.user_id != user_id).count()  # EXCLUDE current user
    
    challenge = Challenge.query.get(challenge_id)
    base_points = challenge.points
    
    if solved_count == 0:
        # First solver - 100% points
        return base_points
    elif solved_count == 1:
        # Second solver - 90% points
        return int(base_points * 0.9)
    elif solved_count == 2:
        # Third solver - 80% points  
        return int(base_points * 0.8)
    else:
        # Fourth+ solver - 50% points (minimum)
        return max(int(base_points * 0.5), 50)

def add_challenges():
    """Add all 9 challenges to the database and create admin user"""
    challenges = [
        # Web Exploitation
        Challenge(
            name="SQL Injection 101",
            category="Web",
            description="Bypass the admin login portal using SQL injection techniques. Analyze the login form to find the vulnerability.",
            flag="sql_injection_bypass",
            points=100,
            file_path="challenges/files/web_sqli_login.html"
        ),
        Challenge(
            name="XSS Cookie Stealer", 
            category="Web",
            description="Steal the admin cookie using XSS vulnerability in the comment system. The admin reviews comments periodically.",
            flag="xss_cookie_theft",
            points=100,
            file_path="challenges/files/web_xss_comment.html"
        ),
        
        # Cryptography
        Challenge(
            name="Caesar Cipher",
            category="Crypto", 
            description="Decrypt the Caesar cipher messages. Both messages use the same shift value between 1-10. Historical hint: Caesar used shift 3.",
            flag="caesar_shift_decoded",
            points=100,
            file_path="challenges/files/crypto_caesar.txt"
        ),
        Challenge(
            name="RSA Factorization",
            category="Crypto",
            description="Factorize the RSA modulus to decrypt the secret message. This number was part of the RSA Factoring Challenge and has known factors.", 
            flag="basic_rsa_decryption",
            points=100,
            file_path="challenges/files/crypto_rsa.py"
        ),
        
        # Reverse Engineering
        Challenge(
            name="Python Crackme",
            category="Reverse",
            description="Reverse engineer the Python password checker to find the correct password. Analyze the obfuscation function carefully.", 
            flag="reverse_engineered",
            points=100,
            file_path="challenges/files/rev_crackme.py"
        ),
        Challenge(
            name="JavaScript Obfuscation",
            category="Reverse", 
            description="Deobfuscate the JavaScript validation logic to find the correct 24-character key. The key undergoes multiple transformations.",
            flag="javascript_reversed",
            points=100,
            file_path="challenges/files/rev_obfuscated.js"
        ),
        
        # OSINT
        Challenge(
            name="Digital Footprint",
            category="Osint",
            description="Investigate Alex Chen's digital presence to find the hidden secret code. Combine clues from his online profiles and research.",
            flag="digital_footprint",
            points=100,
            file_path="challenges/files/osint_investigation.txt"
        ),
        
        # Forensics
        Challenge(
            name="Memory Dump Analysis", 
            category="Forensics",
            description="Analyze the memory dump hex data from a suspicious process. Extract the hidden message using proper encoding analysis.",
            flag="memory_dump",
            points=100,
            file_path="challenges/files/forensics_memory.txt"
        ),
        
        # Steganography
        Challenge(
            name="Hidden in Plain Sight",
            category="Stegano",
            description="Learn about LSB steganography techniques used to hide messages in images. Understand the concept to find the flag.", 
            flag="stego_master",
            points=100,
            file_path="challenges/files/stego_hidden.jpg.txt"
        )
    ]
    
    for challenge in challenges:
        # Check if challenge already exists
        existing = Challenge.query.filter_by(name=challenge.name).first()
        if not existing:
            db.session.add(challenge)
            print(f"✅ Added challenge: {challenge.name}")
    
    # Create admin user if not exists
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        hashed_password = generate_password_hash('admin123')
        admin_user = User(
            teamname='Administrator',
            username='admin',
            password=hashed_password,
            team_id='ADMIN001',
            is_admin=True
        )
        db.session.add(admin_user)
        print("✅ Admin user created: admin / admin123")
    
    db.session.commit()
    print("✅ All challenges added successfully!")

# Database initialization function
def initialize_database():
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Add challenges if none exist
            if Challenge.query.count() == 0:
                add_challenges()
                print("✅ All 9 challenges added!")
            else:
                print("✅ Challenges already exist in database")
                
        except Exception as e:
            print(f"❌ Database initialization error: {e}")

# ==================== MAIN ROUTES ====================

@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        teamname = request.form['teamname']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        team_id = request.form['team_id']
        
        if password != confirm_password:
            return render_template('register.html', error="Passwords don't match")
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already exists")
        
        # Check if teamname already exists
        if User.query.filter_by(teamname=teamname).first():
            return render_template('register.html', error="Team name already exists")
        
        # Check if team ID already exists
        if User.query.filter_by(team_id=team_id).first():
            return render_template('register.html', error="Team ID already registered")
        
        hashed_password = generate_password_hash(password)
        new_user = User(
            teamname=teamname,
            username=username,
            password=hashed_password,
            team_id=team_id
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect('/login?success=Registration successful')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            if user.is_banned:
                return render_template('login.html', error="Your account is banned")
            
            # Check active sessions
            active_sessions = UserSession.query.filter_by(user_id=user.id).count()
            if active_sessions >= 4:
                # Remove oldest session
                oldest_session = UserSession.query.filter_by(user_id=user.id).order_by(UserSession.login_time.asc()).first()
                db.session.delete(oldest_session)
                db.session.commit()
            
            # Create new session
            new_session = UserSession(
                user_id=user.id,
                session_token=secrets.token_hex(16),
                user_agent=request.headers.get('User-Agent'),
                ip_address=request.remote_addr
            )
            db.session.add(new_session)
            db.session.commit()
            
            login_user(user)
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_banned:
        return redirect('/banned')
    
    challenges = Challenge.query.all()
    leaderboard_data = get_leaderboard_data()
    
    # Get user's solved challenges and their points
    user_solved = Submission.query.filter_by(
        user_id=current_user.id, 
        is_correct=True
    ).all()
    solved_challenge_ids = [sub.challenge_id for sub in user_solved]
    
    # Get solving order and points for each challenge
    challenge_solve_info = {}
    for challenge in challenges:
        solvers = Submission.query.filter_by(
            challenge_id=challenge.id,
            is_correct=True
        ).order_by(Submission.timestamp.asc()).all()
        
        challenge_solve_info[challenge.id] = {
            'solvers': [{'teamname': solver.user.teamname, 'points': solver.points_earned} for solver in solvers],
            'solved_count': len(solvers)
        }
    
    return render_template('dashboard.html', 
                         challenges=challenges, 
                         leaderboard=leaderboard_data[:10],
                         solved_challenge_ids=solved_challenge_ids,
                         current_user=current_user,
                         challenge_solve_info=challenge_solve_info)

@app.route('/challenge/<int:challenge_id>')
@login_required
def view_challenge(challenge_id):
    if current_user.is_banned:
        return redirect('/banned')
    
    challenge = Challenge.query.get_or_404(challenge_id)
    
    # Check if current user already solved this challenge
    existing_submission = Submission.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id,
        is_correct=True
    ).first()
    
    if existing_submission:
        # Get solving order information
        solvers = Submission.query.filter_by(
            challenge_id=challenge_id,
            is_correct=True
        ).order_by(Submission.timestamp.asc()).all()
        
        user_rank = next((i+1 for i, s in enumerate(solvers) if s.user_id == current_user.id), None)
        
        return render_template('challenge_solved.html', 
                             challenge=challenge, 
                             user_submission=existing_submission,
                             user_rank=user_rank,
                             total_solvers=len(solvers))
    
    user_attempt = Submission.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    attempt_count = user_attempt.attempt_count if user_attempt else 0
    remaining_attempts = 20 - attempt_count
    
    # Get current solvers count for points information
    solved_count = Submission.query.filter_by(
        challenge_id=challenge_id,
        is_correct=True
    ).count()
    
    potential_points = calculate_points(challenge_id, current_user.id)
    
    return render_template('challenge.html', 
                         challenge=challenge, 
                         attempt_count=attempt_count,
                         remaining_attempts=remaining_attempts,
                         solved_count=solved_count,
                         potential_points=potential_points)

@app.route('/submit_flag/<int:challenge_id>', methods=['POST'])
@login_required
def submit_flag(challenge_id):
    if current_user.is_banned:
        return jsonify({'success': False, 'message': 'You are banned!'})
    
    # Check if user already solved this challenge
    existing_correct = Submission.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id,
        is_correct=True
    ).first()
    
    if existing_correct:
        return jsonify({'success': False, 'message': 'You have already solved this challenge!'})
    
    user_attempt = Submission.query.filter_by(
        user_id=current_user.id,
        challenge_id=challenge_id
    ).first()
    
    if user_attempt and user_attempt.attempt_count >= 20:
        current_user.is_banned = True
        db.session.commit()
        return jsonify({'success': False, 'message': 'Banned - Too many attempts!'})
    
    user_flag = request.form['flag'].strip()
    challenge = Challenge.query.get_or_404(challenge_id)
    
    # UPDATED FLAG VALIDATION - Require Technovaganzactf{} format
    expected_inner_flag = challenge.flag
    expected_full_flag = f"Technovaganzactf{{{expected_inner_flag}}}"
    
    # Check if user submitted the full flag format
    is_correct = (user_flag == expected_full_flag)
    
    if user_attempt:
        user_attempt.attempt_count += 1
        user_attempt.flag_attempt = user_flag
        user_attempt.is_correct = is_correct
        user_attempt.timestamp = datetime.utcnow()
    else:
        user_attempt = Submission(
            user_id=current_user.id,
            challenge_id=challenge_id,
            flag_attempt=user_flag,
            is_correct=is_correct,
            attempt_count=1
        )
        db.session.add(user_attempt)
    
    if is_correct:
        # Calculate points based on solving order
        points_earned = calculate_points(challenge_id, current_user.id)
        user_attempt.points_earned = points_earned
        
        # Update user score
        current_user.score += points_earned
        db.session.commit()
        
        # Get solving rank
        solvers = Submission.query.filter_by(
            challenge_id=challenge_id,
            is_correct=True
        ).order_by(Submission.timestamp.asc()).all()
        user_rank = next((i+1 for i, s in enumerate(solvers) if s.user_id == current_user.id), None)
        
        # Trigger leaderboard update and challenge solved notification
        socketio.emit('leaderboard_update', {'user_id': current_user.id})
        socketio.emit('challenge_solved', {
            'challenge_id': challenge_id,
            'challenge_name': challenge.name,
            'solver_team': current_user.teamname
        })
        
        rank_message = ""
        if user_rank == 1:
            rank_message = " 🥇 First solver!"
        elif user_rank == 2:
            rank_message = " 🥈 Second solver!"
        elif user_rank == 3:
            rank_message = " 🥉 Third solver!"
        else:
            rank_message = f" #{user_rank} solver!"
        
        return jsonify({
            'success': True, 
            'message': f'Correct flag!{rank_message}',
            'rank': user_rank,
            'points': points_earned
        })
    else:
        db.session.commit()
        remaining = 20 - user_attempt.attempt_count
        if remaining <= 0:
            current_user.is_banned = True
            db.session.commit()
            return jsonify({'success': False, 'message': 'Banned - Too many attempts!'})
        
        # Provide helpful error message about flag format
        error_msg = f'Wrong flag! {remaining} attempts remaining.'
        if not user_flag.startswith('Technovaganzactf{'):
            error_msg += ' Remember: flags should be in Technovaganzactf{...} format!'
        
        return jsonify({'success': False, 'message': error_msg})

@app.route('/download_file/<int:challenge_id>')
@login_required
def download_file(challenge_id):
    if current_user.is_banned:
        return redirect('/banned')
    
    challenge = Challenge.query.get_or_404(challenge_id)
    if challenge.file_path and os.path.exists(challenge.file_path):
        return send_file(challenge.file_path, as_attachment=True)
    else:
        return "File not found", 404

@app.route('/leaderboard')
@login_required
def leaderboard():
    if current_user.is_banned:
        return redirect('/banned')
    
    leaderboard_data = get_leaderboard_data()
    
    # Check if JSON response is requested
    if request.args.get('json'):
        return jsonify(leaderboard_data)
    
    return render_template('leaderboard.html', leaderboard=leaderboard_data)

@app.route('/api/leaderboard')
@login_required
def api_leaderboard():
    if current_user.is_banned:
        return jsonify({'error': 'Banned'}), 403
    
    leaderboard_data = get_leaderboard_data()
    return jsonify(leaderboard_data)

def get_leaderboard_data():
    # Use the cached score from User model for better performance
    users = User.query.filter(User.score > 0).order_by(User.score.desc()).all()
    
    leaderboard = []
    for user in users:
        leaderboard.append({
            'teamname': user.teamname,
            'score': user.score
        })
    
    return leaderboard

@app.route('/banned')
def banned():
    return render_template('banned.html')

@app.route('/logout')
@login_required
def logout():
    # Remove user sessions
    UserSession.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    logout_user()
    return redirect('/login')

# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard with overview statistics"""
    # Get statistics
    total_users = User.query.count()
    total_challenges = Challenge.query.count()
    total_submissions = Submission.query.count()
    correct_submissions = Submission.query.filter_by(is_correct=True).count()
    
    # Get recent activity
    recent_submissions = Submission.query.order_by(Submission.timestamp.desc()).limit(10).all()
    
    # Get top players
    top_players = User.query.filter(User.is_admin == False).order_by(User.score.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_challenges=total_challenges,
                         total_submissions=total_submissions,
                         correct_submissions=correct_submissions,
                         recent_submissions=recent_submissions,
                         top_players=top_players)

@app.route('/admin/players')
@login_required
@admin_required
def admin_players():
    """Manage all players"""
    players = User.query.filter(User.is_admin == False).order_by(User.score.desc()).all()
    return render_template('admin_players.html', players=players)

@app.route('/admin/submissions')
@login_required
@admin_required
def admin_submissions():
    """View all submissions"""
    submissions = Submission.query.order_by(Submission.timestamp.desc()).all()
    return render_template('admin_submissions.html', submissions=submissions)

@app.route('/admin/toggle_ban/<int:user_id>')
@login_required
@admin_required
def toggle_ban(user_id):
    """Ban/Unban a player"""
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'success': False, 'message': 'Cannot ban admin users'})
    
    user.is_banned = not user.is_banned
    db.session.commit()
    
    action = "banned" if user.is_banned else "unbanned"
    return jsonify({'success': True, 'message': f'User {user.teamname} {action}', 'is_banned': user.is_banned})

@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user and all their data"""
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'success': False, 'message': 'Cannot delete admin users'})
    
    # Delete user's submissions
    Submission.query.filter_by(user_id=user_id).delete()
    # Delete user's sessions
    UserSession.query.filter_by(user_id=user_id).delete()
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {user.teamname} deleted successfully'})

@app.route('/admin/reset_score/<int:user_id>')
@login_required
@admin_required
def reset_score(user_id):
    """Reset a user's score and submissions"""
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'success': False, 'message': 'Cannot reset admin score'})
    
    # Delete user's submissions
    Submission.query.filter_by(user_id=user_id).delete()
    # Reset score
    user.score = 0
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Score reset for {user.teamname}'})

@app.route('/admin/unauthorized')
def admin_unauthorized():
    """Handle unauthorized admin access attempts"""
    logger.warning(f"Unauthorized admin access attempt from IP: {request.remote_addr}")
    return render_template('unauthorized.html'), 403

# SocketIO events
@socketio.on('connect')
def handle_connect():
    emit('leaderboard_update', {'status': 'connected'})

@socketio.on('request_leaderboard')
def handle_leaderboard_request():
    leaderboard_data = get_leaderboard_data()
    emit('leaderboard_data', {'leaderboard': leaderboard_data})

# Initialize database when app starts
initialize_database()

if __name__ == '__main__':
    # Production-ready server
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)