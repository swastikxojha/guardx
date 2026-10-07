from alembic import context
from app.db.database import Base,engine
from app.db.models import models
config=context.config
target_metadata=Base.metadata
def run_migrations_online():
    with engine.connect() as connection:
        context.configure(connection=connection,target_metadata=target_metadata)
        with context.begin_transaction(): context.run_migrations()
run_migrations_online()
