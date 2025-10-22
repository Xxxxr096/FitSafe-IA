from sqlalchemy import create_engine, inspect
import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv()

# Chemins et connexions
sqlite_url = f"sqlite:///app.db"
mysql_url = os.getenv("DATABASE_URL")

# adapter le format SQLAlchemy
if mysql_url.startswith("mysql://"):
    mysql_url = mysql_url.replace("mysql://", "mysql+pymysql://", 1)

sqlite_engine = create_engine(sqlite_url)
mysql_engine = create_engine(mysql_url)

# Inspecter les tables existantes
inspector = inspect(sqlite_engine)
tables = inspector.get_table_names()

print(f"📦 Tables trouvées dans SQLite : {tables}")

for table in tables:
    print(f"➡️  Migration de {table} ...")
    df = pd.read_sql_table(table, sqlite_engine)
    df.to_sql(table, mysql_engine, index=False, if_exists="replace")
    print(f"✅ Table '{table}' migrée avec succès.")

print("🎉 Migration terminée ! Toutes les tables sont maintenant sur Railway.")
