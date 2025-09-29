from extensions import db
from datetime import datetime

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(300), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    embedding = db.Column(db.JSON, nullable=True)  # Store document embeddings for AI search

    # Relationships
    company = db.relationship('Company', backref=db.backref('documents', cascade='all, delete-orphan'))
    uploader = db.relationship('User', backref=db.backref('uploaded_documents', cascade='all, delete-orphan'))