"""add undo_script to remediation_logs and rollback to remediation_mode

Revision ID: e3f4a5b6c7d8
Revises: c2d3e4f5a6b7
Create Date: 2026-07-11 10:04:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e3f4a5b6c7d8'
down_revision = 'c2d3e4f5a6b7'
branch_labels = None
depends_on = None


def upgrade():
    # Script d'annulation ciblé (rollback individuel) — capturé côté agent
    # avant une remédiation registre, réutilisé tel quel pour l'annuler.
    with op.batch_alter_table('remediation_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('undo_script', sa.Text(), nullable=True))

    # Nouveau mode de journalisation pour une exécution d'annulation
    # (distinct de 'apply', la remédiation initiale).
    op.execute("ALTER TYPE remediation_mode ADD VALUE IF NOT EXISTS 'rollback'")


def downgrade():
    # ALTER TYPE ... DROP VALUE n'existe pas nativement en PostgreSQL —
    # retirer la valeur d'un enum nécessite de recréer le type, ce qui
    # casserait toute ligne l'utilisant déjà. On ne redescend donc que la
    # colonne, pas la valeur d'enum (limite acceptée, cohérente avec le
    # reste des migrations de ce projet).
    with op.batch_alter_table('remediation_logs', schema=None) as batch_op:
        batch_op.drop_column('undo_script')
