"""Instance SQLAlchemy partagée.

Définie dans un module dédié pour éviter les imports circulaires :
les modèles importent `db` d'ici, et l'app factory l'initialise avec
`db.init_app(app)`.
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
