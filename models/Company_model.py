from extensions import db
from datetime import datetime

class Company(db.Model):
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    admin = db.relationship('User', backref='company_admin', uselist=False, foreign_keys=[admin_id])
    users = db.relationship('User', backref='company', lazy=True, foreign_keys='User.company_id')