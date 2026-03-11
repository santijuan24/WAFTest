from sqlalchemy import create_engine, text
from waf_project.config import DATABASE_URL

print('DATABASE_URL', DATABASE_URL)
engine = create_engine(DATABASE_URL)
with engine.connect() as conn:
    result = conn.execute(text('SELECT 1'))
    print('SELECT 1 ->', result.fetchone())
