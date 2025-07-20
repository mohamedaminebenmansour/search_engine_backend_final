from extensions import db
import datetime

class History(db.Model):
    __tablename__ = 'history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    search_query = db.Column(db.String(500), nullable=False)  # Renamed to avoid 'query' conflict
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    conversations = db.relationship('Conversation', backref='history', lazy=True)

    def __repr__(self):
        return f"<History id={self.id} user_id={self.user_id} search_query={self.search_query}>"

class Conversation(db.Model):
    __tablename__ = 'conversation'

    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.Integer, db.ForeignKey('history.id'), nullable=False)
    messages = db.Column(db.Text, nullable=False)
    sources = db.Column(db.Text)

    def __repr__(self):
        return f"<Conversation id={self.id} history_id={self.history_id}>"