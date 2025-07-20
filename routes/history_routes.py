from datetime import datetime
from extensions import db
import json

class History(db.Model):
    __tablename__ = 'history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    query = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    conversation = db.relationship('Conversation', backref='history', uselist=False)  # One-to-one relationship

    def __repr__(self):
        return f'<History {self.query}>'

class Conversation(db.Model):
    __tablename__ = 'conversation'
    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.Integer, db.ForeignKey('history.id'), nullable=False)
    messages = db.Column(db.Text, nullable=False)  # Store messages as JSON string
    sources = db.Column(db.Text, nullable=True)   # Store sources as JSON string

    def __repr__(self):
        return f'<Conversation for History {self.history_id}>'