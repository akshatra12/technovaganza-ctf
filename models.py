from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teamname = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    team_id = db.Column(db.String(50), unique=True, nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    score = db.Column(db.Integer, default=0)
    
    # Relationships
    submissions = db.relationship('Submission', backref='user', lazy=True)

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    flag = db.Column(db.String(100), nullable=False)
    points = db.Column(db.Integer, default=100)
    file_path = db.Column(db.String(200), default="challenges/files/rules.pdf")
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    submissions = db.relationship('Submission', backref='challenge', lazy=True)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    flag_attempt = db.Column(db.String(100))
    is_correct = db.Column(db.Boolean, default=False)
    attempt_count = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    points_earned = db.Column(db.Integer, default=0)
    
    # Performance indexes for PostgreSQL
    __table_args__ = (
        db.UniqueConstraint('user_id', 'challenge_id', name='unique_user_challenge'),
        db.Index('ix_submission_user_id', 'user_id'),
        db.Index('ix_submission_challenge_id', 'challenge_id'),
        db.Index('ix_submission_is_correct', 'is_correct'),
        db.Index('ix_submission_timestamp', 'timestamp'),
    )

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(100), unique=True)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    
    # Performance indexes
    __table_args__ = (
        db.Index('ix_user_session_user_id', 'user_id'),
        db.Index('ix_user_session_login_time', 'login_time'),
    )