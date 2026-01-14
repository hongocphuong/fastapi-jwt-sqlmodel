
# scripts/assign_role.py
import argparse
from sqlmodel import Session
from app.db import engine
from app.crud import assign_role_to_user

parser = argparse.ArgumentParser()
parser.add_argument("--user-id", type=int, required=True)
parser.add_argument("--role", required=True)  # editor, viewer, admin ...
args = parser.parse_args()

with Session(engine) as session:
    roles = assign_role_to_user(session, user_id=args.user_id, role_name=args.role)
    print([r.name for r in roles])
