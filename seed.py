from sqlalchemy import select
from auth import hash_password
from database import SessionLocal, engine, Base
import models

Base.metadata.create_all(engine)

USERS = [
    ("admin@trustvault.test", "Admin#Demo2026", "admin"),
    ("owner@trustvault.test", "Owner#Demo2026", "owner"),
    ("viewer@trustvault.test", "Viewer#Demo2026", "viewer"),
]

with SessionLocal() as db:
    for email, password, role in USERS:
        if db.scalar(select(models.User).where(models.User.email == email)) is None:
            db.add(models.User(email=email, password_hash=hash_password(password), role=role))
    db.commit()
print("seeded")