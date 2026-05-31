"""Enregistrement des Blueprints Flask."""
from app.controllers.audits import audits_bp
from app.controllers.auth import auth_bp
from app.controllers.cis_rules import cis_rules_bp
from app.controllers.health import health_bp
from app.controllers.systems import systems_bp
from app.controllers.agents import agents_bp
from app.controllers.users import users_bp
from app.controllers.account import account_bp
from app.controllers.comparison import comparison_bp
from app.controllers.reports import reports_bp

def register_blueprints(app):
    """Attache tous les Blueprints à l'application."""
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(systems_bp)
    app.register_blueprint(audits_bp)
    app.register_blueprint(cis_rules_bp)
    app.register_blueprint(agents_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(comparison_bp)
    app.register_blueprint(reports_bp)
