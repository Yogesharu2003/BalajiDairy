import sys
import os

# Add parent directory to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, _templates, init_db
from jinja2 import DictLoader

# Initialize template loader for production
app.jinja_loader = DictLoader(_templates)

# Initialize database on cold start
with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"Warning: Database initialization failed: {e}")

# Export for Vercel
handler = app
