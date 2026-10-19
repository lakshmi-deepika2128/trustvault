from database import engine, Base
import models

Base.metadata.create_all(engine)
print("tables created")