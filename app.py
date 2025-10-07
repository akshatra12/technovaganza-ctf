from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
from models import db, User, Challenge, Submission, UserSession
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime
import os

# Production configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'ctf-platform-secret-key-2025')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Database configuration for Render
    if os.environ.get('DATABASE_URL'):
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
    else:
        SQLALCHEMY_DATABASE_URI = 'sqlite:///ctf.db'

app = Flask(__name__)
app.config.from_object(Config)

# Database connection pooling for better performance
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 10,
    'max_overflow': 20
}

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='gevent',
                   logger=True,
                   engineio_logger=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_points(challenge_id, user_id):
    """
    Calculate points based on solving order:
    - 1st solver: 100% points
    - 2nd solver: 90% points  
    - 3rd solver: 80% points
    - 4th+ solver: 50% points (minimum)
    """
    # Count how many teams have already solved this challenge
    solved_count = Submission.query.filter_by(
        challenge_id=challenge_id,
        is_correct=True
    ).count()
    
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
        return max(int(base_points * 0.5), 50)  # At least 50 points

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
    
    # UPDATED FLAG VALIDATION - Remove CTF{} wrapper requirement
    expected_flag = challenge.flag
    if expected_flag.startswith('CTF{') and expected_flag.endswith('}'):
        # Extract inner flag for comparison
        inner_flag = expected_flag[4:-1]
        is_correct = (user_flag == inner_flag) or (user_flag == expected_flag)
    else:
        is_correct = (user_flag == expected_flag)
    
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
            rank_message = " 🥇 First solver! (100% points)"
        elif user_rank == 2:
            rank_message = " 🥈 Second solver! (90% points)"
        elif user_rank == 3:
            rank_message = " 🥉 Third solver! (80% points)"
        else:
            rank_message = f" #{user_rank} solver! (50% points)"
        
        return jsonify({
            'success': True, 
            'message': f'Correct flag! {points_earned} points added.{rank_message}',
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
        return jsonify({'success': False, 'message': f'Wrong flag! {remaining} attempts remaining.'})

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

# FIXED: Single leaderboard route with JSON support
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

# NEW: Separate API endpoint for AJAX calls
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

@socketio.on('connect')
def handle_connect():
    emit('leaderboard_update', {'status': 'connected'})

@socketio.on('request_leaderboard')
def handle_leaderboard_request():
    leaderboard_data = get_leaderboard_data()
    emit('leaderboard_data', {'leaderboard': leaderboard_data})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add sample challenges if none exist
        if Challenge.query.count() == 0:
            challenges = [
                Challenge(
                    name="Web Exploitation 101",
                    category="Web",
                    description="Find the flag hidden in the website. Look for vulnerabilities in the input fields.",
                    flag="web_basic_2024",
                    points=100,
                    file_path="challenges/files/rules.pdf"
                ),
                Challenge(
                    name="Cryptography Challenge",
                    category="Crypto",
                    description="Decrypt the secret message: VGVzdCBmbGFn",  # Base64 encoded "Test flag"
                    flag="crypto_master_2024",
                    points=150,
                    file_path="challenges/files/rules.pdf"
                ),
                Challenge(
                    name="Forensics Investigation",
                    category="Forensics",
                    description="Analyze the image file and find the hidden message.",
                    flag="forensic_expert_2024",
                    points=200,
                    file_path="challenges/files/rules.pdf"
                )
            ]
            db.session.add_all(challenges)
            db.session.commit()
        print("Database initialized successfully!")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)