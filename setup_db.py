import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Connect to default 'postgres' database to create the new db
try:
    con = psycopg2.connect(
        dbname='balaji_dairy',
        user='postgres',
        host='localhost',
        password='yogesh2103',
        port='5432'
    )
    con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = con.cursor()
    
    # Check if db exists
    cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'balaji_dairy'")
    exists = cur.fetchone()
    
    if not exists:
        print("Creating database 'balaji_dairy'...")
        cur.execute('CREATE DATABASE balaji_dairy')
        print("Database created successfully.")
    else:
        print("Database 'balaji_dairy' already exists.")
        
    cur.close()
    con.close()
    
except Exception as e:
    print(f"Error: {e}")
