
import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from sqlmodel import SQLModel

from alembic import context

# alembic/env.py (bổ sung)
#from app.models import User, Item, RefreshToken  # noqa

# --- Alembic Config ---
config = context.config

# Logging theo alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Make project root importable so `app` can be imported when running alembic
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ----- target metadata -----
# Import models để metadata có đầy đủ bảng
from app.models import User, Item, RefreshToken, Role, UserRoleLink, EmailToken, PasswordResetToken  # noqa

target_metadata = SQLModel.metadata

# ----- Lấy URL động từ env (nếu muốn) -----
# Ví dụ đọc từ biến môi trường hoặc .env thông qua pydantic-settings
# Nếu bạn dùng pydantic-settings như trước:
try:
    from app.core.config import settings
    DB_URL = (
        f"postgresql+psycopg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    )
    config.set_main_option("sqlalchemy.url", DB_URL)
except Exception:
    # fallback: dùng URL trong alembic.ini
    pass

def run_migrations_offline():
    """
    Chạy migration ở 'offline mode' (không mở kết nối DB).
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,     # giúp autogenerate so sánh type
        compare_server_default=True
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """
    Chạy migration ở 'online mode' (mở engine và chạy trên DB).
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
