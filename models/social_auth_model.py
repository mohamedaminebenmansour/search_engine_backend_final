# models/social_auth_model.py
from extensions import db

class SocialAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider = db.Column(db.String(50), nullable=False)  # 'google', 'facebook', 'github'
    provider_user_id = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.String(255), nullable=False)
    
    user = db.relationship('User', backref=db.backref('social_auths', lazy=True))
    
    __table_args__ = (
        db.UniqueConstraint('provider', 'provider_user_id', name='uq_provider_user'),
    )