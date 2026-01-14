
import argparse
from sqlmodel import Session, select

from app.db import engine
from app.models import User
from app.core.security import get_password_hash
import os
import sys

# Make project root importable when running this script directly
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

parser = argparse.ArgumentParser(description="Create or update a user with role flags")
parser.add_argument('--email', required=True)
parser.add_argument('--password', required=True)
parser.add_argument('--superuser', default='true', choices=['true', 'false'], help='is_superuser flag')
parser.add_argument('--active', default='true', choices=['true', 'false'], help='is_active flag')
args = parser.parse_args()

is_superuser = args.superuser == 'true'
is_active = args.active == 'true'

with Session(engine) as session:
    user = session.exec(select(User).where(User.email == args.email)).first()
    if user:
        user.hashed_password = get_password_hash(args.password)
        user.is_superuser = is_superuser
        user.is_active = is_active
        session.add(user)
        session.commit()
        print(f"Updated user: {user.email} (superuser={user.is_superuser}, active={user.is_active})")
    else:
        user = User(
            email=args.email,
            hashed_password=get_password_hash(args.password),
            is_superuser=is_superuser,
            is_active=is_active
        )
        session.add(user)
        session.commit()
        print(f"Created user: {user.email} (superuser={user.is_superuser}, active={user.is_active})")
        session.refresh(user)