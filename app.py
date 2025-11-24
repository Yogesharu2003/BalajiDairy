# ---------- BALAJI DAIRY (Elegant White + Emerald + Glass Frosted UI | Responsive) ----------
from flask import (
    Flask, render_template, render_template_string, request, redirect,
    url_for, session, g, flash, jsonify, send_from_directory
)
import os, json, pytz, psycopg2, psycopg2.extras, re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from jinja2 import DictLoader
from datetime import datetime, timedelta, timezone
from collections import defaultdict, OrderedDict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from flask import Flask

# ---------- CONFIG ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "balaji_dairy"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "yogesh2103"),
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": os.environ.get("DB_PORT", "5432"),
}

app = Flask(__name__)
app.secret_key = os.environ.get("FRESHMILK_SECRET") or "replace-this-with-a-secure-random-string"
app.config.update(
    DEBUG=os.environ.get("FLASK_DEBUG", "False").lower() == "true",
    UPLOAD_DIR=UPLOAD_DIR,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

# ---------- DB CONNECTION ----------
def get_conn():
    if not hasattr(g, "pg_conn"):
        g.pg_conn = psycopg2.connect(**DB_CONFIG)
    return g.pg_conn

@app.teardown_appcontext
def close_conn(exception):
    if hasattr(g, "pg_conn"):
        g.pg_conn.close()
        del g.pg_conn

# ---------- DATABASE INIT ----------
def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(200) NOT NULL,
            full_name VARCHAR(200),
            email VARCHAR(200),
            address TEXT,
            phone VARCHAR(50),
            is_admin BOOLEAN DEFAULT FALSE,
            avatar TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(200) NOT NULL,
            description TEXT,
            price NUMERIC(10,2) NOT NULL,
            image TEXT,
            stock INTEGER DEFAULT 0
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            items JSONB,
            total NUMERIC(10,2),
            address TEXT,
            status VARCHAR(50) DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reset_otps (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            email TEXT,
            otp TEXT,
            expires_at TIMESTAMP,
            verified BOOLEAN DEFAULT FALSE
        );
    """)
    conn.commit()
    cur.close()

# ---------- HELPERS ----------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png','jpg','jpeg','gif'}

def validate_password_strength(password):
    """
    Validates password strength.
    Returns: (is_valid: bool, error_message: str)
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""

def get_current_user():
    uid = session.get('user_id')
    if not uid: return None
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
        user = cur.fetchone()
    return user

@app.context_processor
def inject_user_and_cartcount():
    user = get_current_user()
    cart = session.get('cart', {})
    total_items = sum(int(v) for v in cart.values()) if cart else 0
    if not user:
        return dict(current_user=None, cart_count=total_items)

    class U: pass
    u = U()
    u.id = user['id']
    u.username = user['username']
    u.full_name = user.get('full_name')
    u.is_admin = bool(user['is_admin'])
    u.avatar = user.get('avatar')
    u.initial = (u.username[0].upper() if u.username else '?')
    return dict(current_user=u, cart_count=total_items)

# ---------- DECORATORS ----------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or not user['is_admin']:
            flash("Admin access required", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper

# ---------- EMAIL (OTP) ----------
def send_otp_email(to_email, otp):
    try:
        sender = os.environ.get("MAIL_SENDER", "")
        password = os.environ.get("MAIL_PASSWORD", "")
        
        if not sender or not password:
            print("❌ Email credentials not configured. Set MAIL_SENDER and MAIL_PASSWORD environment variables.")
            return False, "Email service not configured. Please contact administrator."
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Balaji Dairy — Password Reset OTP"
        msg["From"] = sender
        msg["To"] = to_email

        html = f"""
        <html><body style="font-family:sans-serif;">
        <h2 style="color:#059669;">Balaji Dairy Password Reset</h2>
        <p>Your OTP: <b style="font-size:24px;color:#059669;">{otp}</b></p>
        <p>Valid for 10 minutes.</p>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(sender, password)
            s.send_message(msg)
        print(f"✅ OTP sent to {to_email}")
        return True, None
    except smtplib.SMTPAuthenticationError:
        print("❌ Email authentication failed. Check MAIL_SENDER and MAIL_PASSWORD.")
        return False, "Email authentication failed. Please check email configuration."
    except Exception as e:
        print(f"❌ Email send failed: {e}")
        return False, f"Failed to send email: {str(e)}"

# ---------- TIME HELPERS ----------
def to_ist_display(dt):
    if not dt: return ''
    if isinstance(dt, str):
        try:
            dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
        except: return dt
    ist = pytz.timezone('Asia/Kolkata')
    return dt.astimezone(ist).strftime('%b %d, %Y %I:%M %p')

def parse_order_items(items_json):
    try:
        # First try to parse as JSON
        if isinstance(items_json, str):
            arr = json.loads(items_json)
        elif isinstance(items_json, list):
            # Already a list (from JSONB in PostgreSQL)
            arr = items_json
        else:
            return [], ''
            
        parsed, names = [], []
        for it in arr:
            parsed.append({
                'id': it.get('id'),
                'name': it.get('name'),
                'qty': int(it.get('qty', 1)),
                'price': float(it.get('price', 0))
            })
            names.append(f"{it.get('name')} x{it.get('qty')}")
        summary = ", ".join(names[:3]) + ("..." if len(names) > 3 else "")
        return parsed, summary
    except json.JSONDecodeError:
        # If JSON parsing fails, try to evaluate as Python literal
        try:
            import ast
            arr = ast.literal_eval(items_json)
            parsed, names = [], []
            for it in arr:
                parsed.append({
                    'id': it.get('id'),
                    'name': it.get('name'),
                    'qty': int(it.get('qty', 1)),
                    'price': float(it.get('price', 0))
                })
                names.append(f"{it.get('name')} x{it.get('qty')}")
            summary = ", ".join(names[:3]) + ("..." if len(names) > 3 else "")
            return parsed, summary
        except Exception as e:
            print(f"[ERROR] Failed to parse items: {e}, items_json type: {type(items_json)}, value: {items_json[:200] if items_json else 'None'}")
            return [], ''
    except Exception as e:
        print(f"[ERROR] Unexpected error parsing items: {e}")
        return [], ''

# ---------- EMBEDDED TEMPLATES ----------
_templates = {}

# Note: Templates are defined below and loaded at module import time
# This ensures they work in both local development and Vercel serverless

# ---------- ROUTES ----------
@app.route('/')
def index():
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM products ORDER BY id DESC;")
    products = cur.fetchall()
    cur.close()
    return render_template('index.html', products=products)

# ---------- BASE HTML WITH RESPONSIVE NAVBAR ----------
_templates["base.html"] = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Balaji Dairy</title>
  <link rel="icon" href="{{ url_for('static', filename='logo.png') }}" type="image/png">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --emerald-600:#059669; --emerald-500:#10b981;
      --blue-dark:#0f172a; --blue-medium:#1e293b; --blue-light:#334155;
      --glass-bg:rgba(255,255,255,0.7); --glass-brd:rgba(255,255,255,0.3);
      --shadow-xl:0 20px 45px rgba(17,24,39,0.08);
    }
    body {
      background:
        radial-gradient(1200px 600px at -10% -20%, rgba(16,185,129,0.06), transparent 60%),
        radial-gradient(900px 500px at 110% 10%, rgba(16,185,129,0.08), transparent 60%),
        linear-gradient(180deg,#f8fafc 0%,#fff 100%);
      color:#111827;
    }
    .glass { background:var(--glass-bg); backdrop-filter:blur(12px); border:1px solid var(--glass-brd); box-shadow:var(--shadow-xl); }
    .btn-emerald{background:linear-gradient(180deg,#10b981,#059669);color:#fff;}
    .btn-emerald:hover{filter:brightness(1.05);transform:translateY(-1px);}
    .btn-ghost{background:rgba(16,185,129,0.1);color:#065f46;}
    .avatar-img{width:36px;height:36px;border-radius:9999px;object-fit:cover;}
    .avatar-circle{width:36px;height:36px;border-radius:9999px;display:flex;align-items:center;justify-content:center;
      font-weight:700;color:#fff;background:linear-gradient(90deg,#10b981,#34d399);}
    .nav-glass{background:rgba(255,255,255,0.9);backdrop-filter:blur(10px);border-bottom:1px solid rgba(0,0,0,0.05);}
    .brand-text{
      background:linear-gradient(90deg,#047857,#10b981);
      -webkit-background-clip:text;
      color:transparent;
      font-weight:800;
      text-shadow:0 0 8px rgba(255,255,255,0.7);
    }
    footer.site-footer{
      background:linear-gradient(180deg, var(--blue-dark) 0%, var(--blue-medium) 100%);
      color:#e2e8f0;
      border-top:2px solid rgba(16,185,129,0.3);
      box-shadow:inset 0 1px 15px rgba(16,185,129,0.15);
      backdrop-filter:blur(10px);
    }
    footer.site-footer h4{color:#10b981;}
    footer.site-footer a{color:#cbd5e1;transition:color 0.3s;}
    footer.site-footer a:hover{color:#34d399;}
    @media (max-width:640px){ #nav-links{display:none;} #menu-btn{display:block;} }
  </style>
</head>
<body class="min-h-screen flex flex-col">

<!-- NAVBAR -->
<nav id="main-nav" class="nav-glass sticky top-0 z-50 w-full">
  <div class="flex justify-between items-center py-3 px-4 sm:px-6 md:px-8">
    <a href="{{ url_for('index') }}" class="text-2xl sm:text-3xl brand-text tracking-tight">Balaji Dairy</a>

    <!-- Hamburger -->
    <button id="menu-btn" class="sm:hidden p-2 rounded hover:bg-emerald-50 focus:outline-none" aria-label="Toggle Menu">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-emerald-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M4 6h16M4 12h16M4 18h16"/>
      </svg>
    </button>

    <!-- Links -->
    <div id="nav-links" class="flex items-center gap-4">
      <a href="{{ url_for('index') }}" class="hover:text-emerald-700 text-gray-700">Home</a>
      <a href="{{ url_for('index') }}#products" class="hover:text-emerald-700 text-gray-700">Products</a>
      {% if current_user %}
        <a href="{{ url_for('user_dashboard') }}" class="hover:text-emerald-700 text-gray-700">Dashboard</a>
        {% if current_user.is_admin %}
          <a href="{{ url_for('admin_dashboard') }}" class="hover:text-emerald-700 text-gray-700">Admin</a>
        {% endif %}
      {% endif %}
      <a href="{{ url_for('cart') }}" class="relative" aria-label="Cart">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 inline-block text-emerald-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13l-2 6h14l-2-6M9 21a1 1 0 100-2
                   1 1 0 000 2zm6 0a1 1 0 100-2 1 1 0 000 2z"/>
        </svg>
        <span id="cart-count-badge"
              class="absolute -top-2 -right-3 bg-emerald-600 text-white rounded-full text-xs px-2">
          {{ cart_count }}
        </span>
      </a>

      {% if current_user %}
        <div class="relative">
          <button id="avatar-btn" class="flex items-center gap-2 focus:outline-none">
            {% if current_user.avatar %}
              <img src="{{ url_for('uploaded_file', filename=current_user.avatar) }}" alt="avatar" class="avatar-img">
            {% else %}
              <div class="avatar-circle" title="{{ current_user.username }}">{{ current_user.initial }}</div>
            {% endif %}
          </button>
          <div id="avatar-menu"
               class="hidden absolute right-0 mt-2 w-44 glass rounded shadow p-2 backdrop-blur-xl">
            <a href="{{ url_for('profile') }}" class="block px-2 py-1 rounded hover:bg-white/50">Change Logo</a>
            <a href="{{ url_for('logout') }}" class="block px-2 py-1 rounded hover:bg-white/50">Logout</a>
          </div>
        </div>
      {% else %}
        <a href="{{ url_for('login') }}" class="btn-ghost px-3 py-1 rounded">Login</a>
        <a href="{{ url_for('register') }}" class="hidden sm:inline-block btn-emerald px-3 py-1 rounded">Register</a>
      {% endif %}
    </div>
  </div>

  <!-- Mobile dropdown -->
  <div id="mobile-menu" class="hidden sm:hidden flex-col gap-2 px-4 pb-4">
    <a href="{{ url_for('index') }}" class="block py-1 text-gray-700 hover:text-emerald-700">Home</a>
    <a href="{{ url_for('index') }}#products" class="block py-1 text-gray-700 hover:text-emerald-700">Products</a>
    {% if current_user %}
      <a href="{{ url_for('user_dashboard') }}" class="block py-1 text-gray-700 hover:text-emerald-700">Dashboard</a>
      {% if current_user.is_admin %}
        <a href="{{ url_for('admin_dashboard') }}" class="block py-1 text-gray-700 hover:text-emerald-700">Admin</a>
      {% endif %}
      <a href="{{ url_for('logout') }}" class="block py-1 text-gray-700 hover:text-emerald-700">Logout</a>
    {% else %}
      <a href="{{ url_for('login') }}" class="block py-1 text-gray-700 hover:text-emerald-700">Login</a>
      <a href="{{ url_for('register') }}" class="block py-1 text-gray-700 hover:text-emerald-700">Register</a>
    {% endif %}
  </div>
</nav>

<!-- BODY -->
<main class="mx-auto px-3 py-8 flex-1 w-full max-w-7xl">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <div class="space-y-2 mb-4">
        {% for category, msg in messages %}
          <div class="glass p-3 rounded {{ 'text-green-800' if category=='success' else
               ('text-red-800' if category=='error' else 'text-emerald-800') }}">{{ msg }}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</main>

<!-- CONDITIONAL FOOTER -->
{% set footer_endpoints = ['index', 'product_detail', 'admin_dashboard', 'user_dashboard'] %}
{% if request.endpoint in footer_endpoints %}
  <footer class="site-footer">
    <div class="mx-auto max-w-7xl px-4 py-8">
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div>
          <h4 class="font-bold mb-3">ADDRESS</h4>
          <div class="text-sm leading-relaxed text-gray-300">
            BALAJI DAIRY,<br>
            Vandavasi Road, Nedungunam,<br>
            Thiruvannamalai Dist - 606 807
          </div>
        </div>
        <div>
          <h4 class="font-bold mb-3">CONTACT US</h4>
          <div class="text-sm leading-relaxed text-gray-300">
            <div class="flex items-center gap-2"><span>📞</span> 9047499400</div>
            <div class="flex items-center gap-2"><span>📞</span> 9715642068</div>
            <div class="flex items-center gap-2"><span>📞</span> 9715868800</div>
            <div class="flex items-center gap-2 mt-2"><span>✉️</span> srinichy1@gmail.com</div>
          </div>
        </div>
        <div>
          <h4 class="font-bold mb-3">IMPORTANT LINKS</h4>
          <ul class="text-sm space-y-2">
            <li><a href="#">Terms and Conditions</a></li>
            <li><a href="#">Privacy Policy</a></li>
            <li><a href="#">Hyperlinking Policy</a></li>
            <li><a href="#">Copyright Policy</a></li>
            <li><a href="#">Disclaimer</a></li>
          </ul>
        </div>
      </div>
    </div>
  </footer>
{% endif %}

<script>
document.addEventListener('DOMContentLoaded', ()=>{
  const menuBtn=document.getElementById('menu-btn');
  const mobileMenu=document.getElementById('mobile-menu');
  const avBtn=document.getElementById('avatar-btn');
  const avMenu=document.getElementById('avatar-menu');
  if(menuBtn){menuBtn.addEventListener('click',()=>mobileMenu.classList.toggle('hidden'));}
  if(avBtn&&avMenu){
    avBtn.addEventListener('click',e=>{e.preventDefault();avMenu.classList.toggle('hidden');});
    document.addEventListener('click',e=>{
      if(!avBtn.contains(e.target)&&!avMenu.contains(e.target))avMenu.classList.add('hidden');
    });
  }
});
</script>
</body></html>
"""


# ---------------- Home / Products ----------------
_templates["index.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <!-- Hero -->
  <section class="glass rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row items-center justify-between gap-6 md:gap-10 mb-8 md:mb-10">
    <div class="flex-1 space-y-3 sm:space-y-4 text-center md:text-left">
      <h1 class="text-3xl sm:text-4xl font-extrabold text-emerald-700 leading-tight">Fresh Milk Delivered to Your Doorstep</h1>
      <p class="text-gray-600 text-base sm:text-lg">From local farms, fresh every morning — purity you can taste.</p>
      <a href="#products" class="inline-block btn-emerald text-white font-medium px-5 sm:px-6 py-2.5 sm:py-3 rounded-lg shadow">🛒 Shop Now</a>
    </div>
    <div class="flex-shrink-0 w-full md:w-1/2">
      <img src="https://i.pinimg.com/736x/99/4e/33/994e338a12b4bd0a18544d5a1f46534c.jpg" alt="Fresh milk" class="w-full max-h-[360px] object-contain rounded-xl shadow-md">
    </div>
  </section>

  <!-- Products -->
  <h2 id="products" class="text-xl sm:text-2xl font-bold mb-4 sm:mb-6 text-gray-800">Our Products</h2>

  {% if products %}
  <div class="grid gap-6 sm:gap-8"
       style="grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));">
    {% for p in products %}
      <div class="glass rounded-xl flex flex-col overflow-hidden">
        <div class="bg-white/60 flex justify-center items-center h-[220px]">
          <img src="{{ p.image or 'https://via.placeholder.com/300x200?text=No+Image' }}" alt="{{ p.name }}"
               class="max-h-[210px] w-auto object-contain rounded">
        </div>

        <div class="p-4 sm:p-5 flex-1 flex flex-col justify-between">
          <div>
            <h3 class="text-base sm:text-lg font-semibold text-gray-900">{{ p.name }}</h3>
            <p class="text-sm text-gray-600 mt-1 line-clamp-2">{{ p.description or "No description available." }}</p>
          </div>

          <div class="mt-4 flex justify-between items-center text-sm sm:text-base">
            <div class="text-lg sm:text-xl font-bold text-emerald-600">₹{{ '%.2f'|format(p.price) }}</div>
            <div>
              {% if p.stock == 0 %}
                <span class="text-red-600 text-xs sm:text-sm font-semibold">Out of Stock</span>
              {% else %}
                <span class="text-gray-600 text-xs sm:text-sm">Stock: <strong>{{ p.stock }}</strong></span>
              {% endif %}
            </div>
          </div>

          <div class="mt-4 sm:mt-5 flex items-center justify-between gap-3">
            <div class="qty-widget flex items-center space-x-2 w-full sm:w-auto" data-product-id="{{ p.id }}">
              <button class="qty-sub bg-white/70 hover:bg-white px-3 py-2 rounded-lg text-base">−</button>
              <input type="number" class="qty-input w-20 text-center border rounded-lg px-2 py-2 focus:ring-2 focus:ring-emerald-400 focus:outline-none"
                     value="1" min="1" {% if p.stock == 0 %}disabled{% endif %}>
              <button class="qty-add bg-white/70 hover:bg-white px-3 py-2 rounded-lg text-base">+</button>
            </div>
            {% if p.stock == 0 %}
              <button class="add-cart-btn btn-emerald px-4 py-2 rounded-lg opacity-60 cursor-not-allowed w-full sm:w-auto" disabled>Out of Stock</button>
            {% else %}
              <button class="add-cart-btn btn-emerald px-4 py-2 rounded-lg shadow w-full sm:w-auto">Add</button>
            {% endif %}
          </div>

          <div class="mt-3 text-right">
            <a href="{{ url_for('product_detail', product_id=p.id) }}" class="text-emerald-700 hover:underline text-sm sm:text-base">View details →</a>
          </div>
        </div>
      </div>
    {% endfor %}
  </div>
  {% else %}
    <p class="text-gray-600">No products available at the moment.</p>
  {% endif %}

  <script>
    function showToast(msg){
      const toast = document.createElement('div');
      toast.innerHTML = msg;
      toast.className = "glass px-4 py-3 rounded-lg shadow-lg fixed bottom-5 right-5 z-50";
      document.body.appendChild(toast);
      setTimeout(()=> toast.remove(), 2200);
    }
    function setCartCount(count){
      const el = document.getElementById('cart-count-badge');
      if(el) el.textContent = count;
    }
    async function addToCartAjax(productId, qty){
      try{
        const form = new FormData();
        form.append('product_id', productId);
        form.append('qty', qty);
        const resp = await fetch('{{ url_for("api_cart_add") }}', { method: 'POST', credentials: 'same-origin', body: form });
        const data = await resp.json();
        if(!resp.ok){ showToast(data.error || 'Could not add to cart'); return; }
        setCartCount(data.total_items || 0);
        showToast(`✅ Added ${qty} × ${data.product_name || 'item'} to cart`);
      }catch(err){ console.error(err); showToast('❌ Error adding to cart'); }
    }
    document.addEventListener('DOMContentLoaded', ()=>{
      document.querySelectorAll('.qty-widget').forEach(widget => {
        const input = widget.querySelector('.qty-input');
        const btnAdd = widget.querySelector('.qty-add');
        const btnSub = widget.querySelector('.qty-sub');
        const productId = widget.dataset.productId;
        const addCartBtn = widget.parentElement.querySelector('.add-cart-btn');
        btnAdd?.addEventListener('click', e=>{ e.preventDefault(); input.value = (parseInt(input.value)||0) + 1; });
        btnSub?.addEventListener('click', e=>{ e.preventDefault(); input.value = Math.max(1,(parseInt(input.value)||1)-1); });
        addCartBtn?.addEventListener('click', e=>{ e.preventDefault(); addToCartAjax(productId, parseInt(input.value)||1); });
      });
    });
  </script>
{% endblock %}
"""

_templates["product.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <div class="max-w-5xl mx-auto glass p-4 sm:p-6 rounded shadow">
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
      <div class="glass-soft rounded p-2 soft-border">
        <img src="{{ product.image or 'https://via.placeholder.com/300x200?text=No+Image' }}" alt="{{ product.name }}" class="w-full h-72 sm:h-80 object-cover rounded">
      </div>
      <div>
        <h1 class="text-xl sm:text-2xl font-bold text-emerald-700">{{ product.name }}</h1>
        <p class="mt-2 text-sm sm:text-base text-gray-600">{{ product.description }}</p>
        <div class="mt-3 sm:mt-4 text-xl sm:text-2xl font-semibold text-emerald-700">₹{{ '%.2f'|format(product.price) }}</div>
        <div class="mt-2 text-sm text-gray-600">
          {% if product.stock == 0 %}
            <span class="badge bg-red-100 text-red-700">Out of Stock</span>
          {% else %}
            Stock: <strong>{{ product.stock }}</strong>
          {% endif %}
        </div>
        <form action="{{ url_for('add_to_cart', product_id=product.id) }}" method="post" class="mt-4 flex flex-wrap items-center gap-3">
          <label class="block text-sm">Qty</label>
          <input type="number" name="qty" value="1" min="1" class="border rounded px-2 py-2 w-24" {% if product.stock==0 %}disabled{% endif %}>
          <button class="btn-emerald text-white px-4 py-2 rounded {% if product.stock==0 %}opacity-60 cursor-not-allowed{% endif %}">Add to Cart</button>
        </form>
      </div>
    </div>
  </div>
{% endblock %}
"""

# ---------------- Cart / Checkout ----------------
_templates["cart.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <h2 class="text-lg sm:text-xl font-semibold mb-3 sm:mb-4">Your Cart</h2>
  {% if items %}
    <div class="glass rounded p-3 sm:p-4">
      <div class="overflow-x-auto -mx-2 sm:mx-0">
        <table class="w-full text-left min-w-[560px] sm:min-w-0">
          <thead class="table-head">
            <tr>
              <th class="py-2 px-3">Item</th>
              <th class="py-2 px-3">Qty</th>
              <th class="py-2 px-3">Subtotal</th>
              <th class="py-2 px-3"></th>
            </tr>
          </thead>
          <tbody>
            {% for it in items %}
              <tr class="border-t hover:bg-white/50">
                <td class="py-2 px-3">{{ it.product.name }}</td>
                <td class="py-2 px-3">{{ it.qty }}</td>
                <td class="py-2 px-3">₹{{ '%.2f'|format(it.subtotal) }}</td>
                <td class="py-2 px-3">
                  <form method="post" action="{{ url_for('remove_from_cart', product_id=it.product.id) }}">
                    <button class="text-red-600 hover:underline">Remove</button>
                  </form>
                </td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="mt-4 flex flex-col sm:flex-row gap-3 sm:gap-0 sm:justify-between sm:items-center">
        <div class="text-lg font-semibold">Total: ₹{{ '%.2f'|format(total) }}</div>
        <div class="flex flex-col sm:flex-row gap-2">
          <a href="/" class="btn-ghost px-3 py-2 rounded text-center">Continue Shopping</a>
          {% if current_user %}
            <a href="{{ url_for('checkout') }}" class="btn-emerald px-4 py-2 rounded text-center">Checkout</a>
          {% else %}
            <a href="{{ url_for('login') }}" class="btn-emerald px-4 py-2 rounded text-center">Login to Checkout</a>
          {% endif %}
        </div>
      </div>
    </div>
  {% else %}
    <div class="glass p-6 rounded">Your cart is empty.</div>
  {% endif %}
{% endblock %}
"""

_templates["checkout.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <h2 class="text-lg sm:text-xl font-semibold mb-3 sm:mb-4">Checkout</h2>
  <div class="glass rounded p-4 sm:p-6">
    <form method="post" class="space-y-4">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Delivery Address</label>
        <textarea name="address" class="w-full border rounded p-2" rows="3" required>{{ user.address if user else '' }}</textarea>
      </div>

      <div>
        <h3 class="font-semibold">Order Summary</h3>
        <ul class="divide-y mt-2 text-sm">
          {% for it in items %}
            <li class="py-2 flex justify-between"><div>{{ it.product.name }} x {{ it.qty }}</div><div>₹{{ '%.2f'|format(it.subtotal) }}</div></li>
          {% endfor %}
        </ul>
        <div class="mt-3 text-right font-bold">Total: ₹{{ '%.2f'|format(total) }}</div>
      </div>

      <div>
        <button class="btn-emerald px-4 py-2 rounded w-full sm:w-auto">Place Order (no payment)</button>
      </div>
    </form>
  </div>
{% endblock %}
"""

# ---------------- Auth / Profile ----------------
_templates["login.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <div class="max-w-md mx-auto glass p-6 rounded shadow-lg">
    <h2 class="text-2xl font-bold text-emerald-700 mb-4 text-center">Welcome Back</h2>
    <p class="text-sm text-gray-600 text-center mb-6">Login to continue your Balaji Dairy experience</p>
    <form method="post" class="space-y-4">
      <div>
        <label class="block text-sm mb-1 font-medium">Username</label>
        <input name="username" class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400" required>
      </div>
      <div>
        <label class="block text-sm mb-1 font-medium">Password</label>
        <input name="password" type="password" class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400" required>
      </div>
      <div class="flex justify-between items-center text-sm">
        <a href="{{ url_for('forgot_password') }}" class="text-emerald-700 hover:underline">Forgot password?</a>
        <a href="{{ url_for('register') }}" class="text-gray-600 hover:text-emerald-700 hover:underline">Don’t have an account?</a>
      </div>
      <button class="w-full btn-emerald py-2.5 rounded-lg font-semibold shadow mt-3">Login</button>
    </form>
  </div>
{% endblock %}
"""


_templates["register.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <div class="max-w-md mx-auto glass p-6 rounded shadow-lg">
    <h2 class="text-2xl font-bold text-emerald-700 mb-4 text-center">Create an Account</h2>
    <p class="text-sm text-gray-600 text-center mb-6">Join Balaji Dairy and get fresh milk delivered daily</p>
    <form method="post" class="space-y-4" id="register-form">
      <div>
        <label class="block text-sm mb-1 font-medium">Username</label>
        <input name="username" class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400" required>
      </div>
      <div>
        <label class="block text-sm mb-1 font-medium">Email ID</label>
        <input name="email" type="email" class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400" required>
      </div>
      <div>
        <label class="block text-sm mb-1 font-medium">Password</label>
        <input id="password" name="password" type="password" class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400" required>
        <div id="password-strength" class="mt-1 h-2 bg-gray-200 rounded overflow-hidden">
          <div id="strength-bar" class="h-2 bg-red-400 w-0 transition-all duration-300"></div>
        </div>
        <p id="strength-text" class="text-xs text-gray-500 mt-1">Enter a strong password</p>
        
        <!-- Password Requirements Checklist -->
        <div class="mt-2 text-xs space-y-1">
          <div id="req-length" class="flex items-center gap-1 text-gray-500">
            <span class="req-icon">○</span> At least 8 characters
          </div>
          <div id="req-upper" class="flex items-center gap-1 text-gray-500">
            <span class="req-icon">○</span> One uppercase letter
          </div>
          <div id="req-lower" class="flex items-center gap-1 text-gray-500">
            <span class="req-icon">○</span> One lowercase letter
          </div>
          <div id="req-number" class="flex items-center gap-1 text-gray-500">
            <span class="req-icon">○</span> One number
          </div>
          <div id="req-special" class="flex items-center gap-1 text-gray-500">
            <span class="req-icon">○</span> One special character
          </div>
        </div>
      </div>
      <div>
        <label class="block text-sm mb-1 font-medium">Phone</label>
        <input name="phone" class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400">
      </div>
      <div>
        <label class="block text-sm mb-1 font-medium">Address</label>
        <textarea name="address" class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400" rows="3"></textarea>
      </div>
      <button class="w-full btn-emerald py-2.5 rounded-lg font-semibold shadow mt-3">Register</button>
      <div class="text-center text-sm mt-3">
        Already have an account? <a href="{{ url_for('login') }}" class="text-emerald-700 hover:underline">Login here</a>
      </div>
    </form>

    <script>
      const passwordInput = document.getElementById('password');
      const strengthBar = document.getElementById('strength-bar');
      const strengthText = document.getElementById('strength-text');
      
      const reqLength = document.getElementById('req-length');
      const reqUpper = document.getElementById('req-upper');
      const reqLower = document.getElementById('req-lower');
      const reqNumber = document.getElementById('req-number');
      const reqSpecial = document.getElementById('req-special');

      function updateRequirement(element, met) {
        const icon = element.querySelector('.req-icon');
        if (met) {
          element.className = 'flex items-center gap-1 text-green-600';
          icon.textContent = '✓';
        } else {
          element.className = 'flex items-center gap-1 text-gray-500';
          icon.textContent = '○';
        }
      }

      passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;
        let strength = 0;
        
        // Check each requirement
        const hasLength = val.length >= 8;
        const hasUpper = /[A-Z]/.test(val);
        const hasLower = /[a-z]/.test(val);
        const hasNumber = /[0-9]/.test(val);
        const hasSpecial = /[^A-Za-z0-9]/.test(val);
        
        // Update visual indicators
        updateRequirement(reqLength, hasLength);
        updateRequirement(reqUpper, hasUpper);
        updateRequirement(reqLower, hasLower);
        updateRequirement(reqNumber, hasNumber);
        updateRequirement(reqSpecial, hasSpecial);
        
        // Calculate strength
        if (hasLength) strength++;
        if (hasUpper) strength++;
        if (hasLower) strength++;
        if (hasNumber) strength++;
        if (hasSpecial) strength++;

        const percent = (strength / 5) * 100;
        strengthBar.style.width = percent + '%';

        if (strength <= 2) {
          strengthBar.className = 'h-2 bg-red-400 transition-all duration-300';
          strengthText.textContent = 'Weak password';
          strengthText.className = 'text-xs text-red-500 mt-1';
        } else if (strength === 3 || strength === 4) {
          strengthBar.className = 'h-2 bg-yellow-400 transition-all duration-300';
          strengthText.textContent = 'Medium strength';
          strengthText.className = 'text-xs text-yellow-500 mt-1';
        } else {
          strengthBar.className = 'h-2 bg-green-500 transition-all duration-300';
          strengthText.textContent = 'Strong password ✓';
          strengthText.className = 'text-xs text-green-600 mt-1';
        }
      });
    </script>
  </div>
{% endblock %}
"""

_templates["profile.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <div class="max-w-md mx-auto glass p-4 sm:p-6 rounded">
    <h2 class="text-xl font-semibold mb-4">Change Logo / Avatar</h2>
    <div class="mb-4">
      {% if user.avatar %}
        <img src="{{ url_for('uploaded_file', filename=user.avatar) }}" class="w-24 h-24 rounded-full object-cover">
      {% else %}
        <div class="w-24 h-24 rounded-full bg-emerald-200 flex items-center justify-center text-2xl font-semibold text-emerald-700">{{ user.initial }}</div>
      {% endif %}
    </div>

    <form method="post" enctype="multipart/form-data" class="space-y-3">
      <div>
        <label class="block text-sm mb-1">Upload image (png/jpg/jpeg/gif) - max 2MB</label>
        <input type="file" name="avatar" accept="image/*" class="mt-1">
      </div>
      <div class="flex flex-col sm:flex-row gap-2">
        <button class="btn-emerald text-white px-3 py-2 rounded w-full sm:w-auto">Upload</button>
        <a href="{{ url_for('profile_remove') }}" class="px-3 py-2 rounded border text-center w-full sm:w-auto">Remove</a>
      </div>
    </form>
  </div>
{% endblock %}
"""

# ---------------- User Dashboard ----------------
_templates["dashboard_user.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <h2 class="text-2xl font-bold text-emerald-700 mb-4 sm:mb-6">Your Dashboard</h2>

  <!-- Quick Stats -->
  <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4 mb-4" id="user-stats">
    <div class="p-4 rounded-2xl bg-gradient-to-br from-emerald-50 to-white shadow-sm backdrop-blur-md border border-emerald-100">
      <div class="text-sm text-gray-500">Total Orders</div>
      <div class="text-2xl font-bold text-emerald-700">{{ orders|length }}</div>
    </div>
    <div class="p-4 rounded-2xl bg-gradient-to-br from-emerald-50 to-white shadow-sm backdrop-blur-md border border-emerald-100">
      <div class="text-sm text-gray-500">Delivered Orders</div>
      <div class="text-2xl font-bold text-emerald-700">
        {{ orders | selectattr('status','equalto','Delivered') | list | length }}
      </div>
    </div>
    <div class="p-4 rounded-2xl bg-gradient-to-br from-emerald-50 to-white shadow-sm backdrop-blur-md border border-emerald-100">
      <div class="text-sm text-gray-500">Total Spent</div>
      <div class="text-2xl font-bold text-emerald-700">
        ₹{{ orders | map(attribute='total') | sum | round(2) }}
      </div>
    </div>
  </div>

  <!-- Filter Bar -->
  <div class="bg-white/80 backdrop-blur-md rounded-xl p-3 sm:p-4 shadow mb-4 sm:mb-6 flex flex-col md:flex-row md:justify-between gap-3 border border-emerald-50">
    <div>
      <h3 class="font-semibold text-gray-800">Order History</h3>
      <div class="text-sm text-gray-500">Filter your orders by date range</div>
    </div>
    <div class="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
      <input type="date" id="user-filter-start" class="border rounded px-2 py-2 focus:ring-2 focus:ring-emerald-400 w-full sm:w-auto">
      <input type="date" id="user-filter-end" class="border rounded px-2 py-2 focus:ring-2 focus:ring-emerald-400 w-full sm:w-auto">
      <div class="flex gap-2">
        <button id="user-filter-apply" class="bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-2 rounded shadow w-full sm:w-auto">Apply</button>
        <button id="user-filter-reset" class="px-3 py-2 rounded border w-full sm:w-auto">Reset</button>
      </div>
    </div>
  </div>

  <!-- Orders List -->
  <div id="user-orders-wrapper" class="space-y-3 sm:space-y-4">
    {% if orders %}
      {% for o in orders %}
        <div class="order-card transition bg-white/80 backdrop-blur-md border border-emerald-100 p-4 sm:p-5 rounded-2xl shadow-sm">
          <div class="flex flex-col sm:flex-row sm:justify-between gap-3">
            <div>
              <div class="text-base font-semibold text-emerald-700">Order #{{ o.id }}</div>
              <div class="text-sm text-gray-500 mt-1">{{ o.created_at }}</div>
              <div class="text-sm text-gray-600 mt-2">Items: {{ o.items_summary }}</div>
            </div>
            <div class="text-left sm:text-right">
              <div class="text-sm text-gray-500 mb-1">Total</div>
              <div class="text-lg font-bold text-emerald-700">₹{{ '%.2f'|format(o.total) }}</div>
              <div class="mt-2">
                <span class="px-3 py-1 rounded-full text-xs font-medium
                  {% if o.status == 'Pending' %} bg-yellow-100 text-yellow-800
                  {% elif o.status == 'Confirmed' %} bg-blue-100 text-blue-800
                  {% elif o.status == 'Out for Delivery' %} bg-purple-100 text-purple-800
                  {% elif o.status == 'Delivered' %} bg-green-100 text-green-800
                  {% else %} bg-gray-100 text-gray-700{% endif %}">
                  {{ o.status }}
                </span>
              </div>
            </div>
          </div>

          <!-- Actions -->
          <div class="mt-4 flex justify-between items-center">
            <a href="{{ url_for('view_order', order_id=o.id) }}" class="text-sm font-medium text-emerald-700 hover:underline">View Details →</a>
            {% if o.status == 'Pending' %}
              <form method="post" action="{{ url_for('cancel_order', order_id=o.id) }}"
                    onsubmit="return confirm('Cancel order #{{ o.id }}?');">
                <button class="text-sm text-red-600 hover:underline">Cancel</button>
              </form>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    {% else %}
      <div class="text-center py-10 bg-white/80 backdrop-blur-md border border-emerald-100 rounded-xl text-gray-500">
        No orders yet. Start shopping to see your history here!
      </div>
    {% endif %}
  </div>

  <!-- JS: Filter Logic -->
  <script>
  async function fetchUserOrdersFragment(start, end){
    const params = new URLSearchParams();
    if(start) params.set('start', start);
    if(end) params.set('end', end);
    const resp = await fetch('{{ url_for("user_orders_fragment") }}?' + params.toString());
    if(!resp.ok) return;
    const html = await resp.text();
    document.getElementById('user-orders-wrapper').innerHTML = html;
  }

  async function fetchUserStatsFragment(start, end){
    const params = new URLSearchParams();
    if(start) params.set('start', start);
    if(end) params.set('end', end);
    const resp = await fetch('{{ url_for("user_stats_fragment") }}?' + params.toString());
    if(!resp.ok) return;
    const html = await resp.text();
    const box = document.getElementById('user-stats');
    if (box) box.innerHTML = html;
  }

  document.addEventListener('DOMContentLoaded', ()=>{
    const startEl = document.getElementById('user-filter-start');
    const endEl   = document.getElementById('user-filter-end');
    const applyBtn = document.getElementById('user-filter-apply');
    const resetBtn = document.getElementById('user-filter-reset');

    applyBtn.addEventListener('click', async ()=>{
      const s = startEl.value;
      const e = endEl.value;
      applyBtn.disabled = true;
      await Promise.all([
        fetchUserOrdersFragment(s, e),
        fetchUserStatsFragment(s, e)
      ]);
      applyBtn.disabled = false;
    });

    resetBtn.addEventListener('click', async ()=>{
      startEl.value = '';
      endEl.value = '';
      resetBtn.disabled = true;
      await Promise.all([
        fetchUserOrdersFragment('', ''),
        fetchUserStatsFragment('', '')
      ]);
      resetBtn.disabled = false;
    });
  });
  </script>
{% endblock %}
"""

# ---------------- Admin Dashboard ----------------
_templates["dashboard_admin.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <h2 class="text-xl sm:text-2xl font-semibold mb-3 sm:mb-4">Admin Dashboard</h2>

  <!-- Filter + Chart (Glass) -->
  <div class="glass p-3 sm:p-4 rounded mb-4 sm:mb-6">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
      <div class="flex items-center gap-2 sm:gap-3 flex-wrap">
        <div class="text-sm font-medium">Period:</div>
        <div class="flex gap-2 flex-wrap">
          <button class="period-btn px-3 py-1.5 rounded btn-emerald text-white" data-period="day">Daily</button>
          <button class="period-btn px-3 py-1.5 rounded btn-ghost" data-period="week">Weekly</button>
          <button class="period-btn px-3 py-1.5 rounded btn-ghost" data-period="month">Monthly</button>
          <button class="period-btn px-3 py-1.5 rounded btn-ghost" data-period="year">Yearly</button>
        </div>
      </div>

      <div class="flex items-stretch md:items-center gap-2 flex-col sm:flex-row">
        <div class="text-sm small-muted sm:self-center">From</div>
        <input type="date" id="filter-start" class="border rounded px-2 py-2">
        <div class="text-sm small-muted sm:self-center">To</div>
        <input type="date" id="filter-end" class="border rounded px-2 py-2">
        <div class="flex gap-2">
          <button id="filter-apply" class="btn-emerald text-white px-3 py-2 rounded">Apply</button>
          <button id="filter-reset" class="px-3 py-2 rounded border">Reset</button>
        </div>
      </div>
    </div>

    <div class="mt-4">
      <!-- Chart.js CDN (ensures availability even if base omitted it) -->
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <canvas id="salesChart" height="120" class="w-full"></canvas>
    </div>
  </div>

  <!-- Product Management + Quick Stats -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6">
    <div class="col-span-1 md:col-span-2 glass p-3 sm:p-4 rounded">
      <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 mb-3 sm:mb-4">
        <h3 class="font-semibold">Product Management</h3>
        <a href="{{ url_for('admin_add_product') }}" class="btn-emerald text-white px-3 py-2 rounded text-center">Add Product</a>
      </div>

      <div class="overflow-x-auto -mx-2 sm:mx-0">
        <table class="w-full text-left min-w-[720px] sm:min-w-0 rounded border-collapse">
          <thead class="table-head">
            <tr>
              <th class="py-3 px-4">Image</th>
              <th class="py-3 px-4">Name</th>
              <th class="py-3 px-4">Description</th>
              <th class="py-3 px-4">Price</th>
              <th class="py-3 px-4">Stock</th>
              <th class="py-3 px-4">Actions</th>
            </tr>
          </thead>
          <tbody id="products-table-body" class="bg-white/40">
            {% for p in products %}
              <tr class="border-t hover:bg-white/70">
                <td class="py-3 px-4"><img src="{{ p.image or 'https://via.placeholder.com/100x100?text=No' }}" class="w-12 h-12 rounded-full object-cover"></td>
                <td class="py-3 px-4 font-medium">{{ p.name }}</td>
                <td class="py-3 px-4 small-muted">{{ p.description }}</td>
                <td class="py-3 px-4">₹{{ '%.2f'|format(p.price) }}</td>
                <td class="py-3 px-4">
                  {% if p.stock == 0 %}
                    <span class="badge bg-red-100 text-red-700">Out of Stock</span>
                  {% else %}
                    {{ p.stock }}
                  {% endif %}
                </td>
                <td class="py-3 px-4">
                  <a href="{{ url_for('admin_edit_product', product_id=p.id) }}" class="text-sm underline mr-3">Edit</a>
                  <form method="post" action="{{ url_for('admin_delete_product', product_id=p.id) }}" style="display:inline;" onsubmit="return confirm('Delete product {{ p.name }}?');">
                    <button class="text-red-600 text-sm">Delete</button>
                  </form>
                </td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

    </div>

    <div class="glass p-4 rounded" id="quick-stats-box">
      <h3 class="font-semibold mb-3">Quick Stats</h3>
      <div class="space-y-3" id="quick-stats-content">
        <div>Total users: <strong>{{ stats.users }}</strong></div>
        <div>Total orders: <strong>{{ stats.orders }}</strong></div>
        <div>Revenue: <strong>₹{{ '%.2f'|format(stats.revenue) }}</strong></div>
      </div>
    </div>
  </div>

  <!-- Orders by User -->
  <div class="mt-4 sm:mt-6 glass p-3 sm:p-4 rounded" id="orders-section">
    <h3 class="font-semibold mb-3">Orders by User</h3>
    <div id="orders-wrapper">
      {% if daywise %}
        {% for day, orders in daywise.items() %}
          <div class="mb-4 sm:mb-6 border border-white/50 rounded-lg overflow-hidden">
            <div class="bg-emerald-50/80 px-4 py-2 text-sm font-semibold text-emerald-800 border-b border-emerald-100">
              {{ day }} — {{ orders|length }} order{{ 's' if orders|length > 1 else '' }}
            </div>
            <div class="overflow-x-auto -mx-2 sm:mx-0">
              <table class="w-full text-left text-sm border-collapse min-w-[720px] sm:min-w-0">
                <thead class="bg-emerald-100 text-emerald-900">
                  <tr>
                    <th class="py-2 px-4 font-semibold text-left">Order</th>
                    <th class="py-2 px-4 font-semibold text-left">User</th>
                    <th class="py-2 px-4 font-semibold text-left">Items</th>
                    <th class="py-2 px-4 font-semibold text-right">Total</th>
                    <th class="py-2 px-4 font-semibold text-left">Status</th>
                    <th class="py-2 px-4 font-semibold text-center">Action</th>
                  </tr>
                </thead>
                <tbody class="bg-white/50">
                  {% for o in orders %}
                    <tr class="border-t hover:bg-white/70 transition">
                      <td class="py-2 px-4 align-top">
                        <div class="font-medium text-gray-800">#{{ o.id }}</div>
                        <div class="text-xs text-gray-500">{{ o.created_at }}</div>
                      </td>
                      <td class="py-2 px-4 align-top">
                        {{ o.username or ('User ' + (o.user_id|string)) }}
                      </td>
                      <td class="py-2 px-4 align-top text-gray-700">
                        {{ o.items_summary }}
                      </td>
                      <td class="py-2 px-4 align-top text-right font-semibold text-gray-800">
                        ₹{{ '%.2f'|format(o.total) }}
                      </td>
                      <td class="py-2 px-4 align-top">
                        <span class="badge
                          {% if o.status == 'Pending' %} bg-yellow-100 text-yellow-800
                          {% elif o.status == 'Confirmed' %} bg-blue-100 text-blue-800
                          {% elif o.status == 'Out for Delivery' %} bg-purple-100 text-purple-800
                          {% elif o.status == 'Delivered' %} bg-green-100 text-green-800
                          {% else %} bg-gray-100 text-gray-700{% endif %}
                        ">{{ o.status }}</span>
                      </td>
                      <td class="py-2 px-4 text-center">
                        <div class="flex items-center justify-center gap-2">
                          <a href="{{ url_for('view_order', order_id=o.id) }}" class="text-sm text-emerald-700 hover:underline">View</a>
                          <form method="post" action="{{ url_for('admin_update_order', order_id=o.id) }}" class="flex items-center gap-2">
                            <select name="status" class="border rounded px-2 py-1 text-sm focus:ring-emerald-400 focus:border-emerald-400">
                              <option {{ 'selected' if o.status=='Pending' else '' }}>Pending</option>
                              <option {{ 'selected' if o.status=='Confirmed' else '' }}>Confirmed</option>
                              <option {{ 'selected' if o.status=='Out for Delivery' else '' }}>Out for Delivery</option>
                              <option {{ 'selected' if o.status=='Delivered' else '' }}>Delivered</option>
                            </select>
                            <button class="btn-emerald text-white px-2 py-1 rounded text-sm">Update</button>
                          </form>
                          <form method="post" action="{{ url_for('delete_order', order_id=o.id) }}" onsubmit="return confirm('Delete order #{{ o.id }}?');">
                            <button class="text-red-600 text-sm hover:underline">Delete</button>
                          </form>
                        </div>
                      </td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
          </div>
        {% endfor %}
      {% else %}
        <div class="text-gray-600 text-center py-6 border border-gray-100 rounded">
          No orders yet.
        </div>
      {% endif %}
    </div>
  </div>

<script>
  let salesChart = null;
  let currentPeriod = 'day';

  async function fetchSalesAndRender(period, start, end){
    const params = new URLSearchParams();
    if(period) params.set('period', period);
    if(start) params.set('start', start);
    if(end) params.set('end', end);
    const resp = await fetch('{{ url_for("admin_sales_data") }}?' + params.toString());
    const data = await resp.json();
    const labels = data.labels || [];
    const values = data.values || [];
    const ctx = document.getElementById('salesChart').getContext('2d');
    if(salesChart) salesChart.destroy();
    salesChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Sales (₹)',
          data: values,
          fill: true,
          tension: 0.25,
          borderColor: 'rgba(16,185,129,0.95)',
          backgroundColor: 'rgba(16,185,129,0.12)',
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { display: true },
          y: { display: true, title: { display: true, text: '₹' } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  async function fetchOrdersFilteredAndRender(start, end){
    const params = new URLSearchParams();
    if(start) params.set('start', start);
    if(end) params.set('end', end);
    const resp = await fetch('{{ url_for("admin_orders_fragment") }}?' + params.toString());
    if(!resp.ok) return;
    const html = await resp.text();
    document.getElementById('orders-wrapper').innerHTML = html;
  }

  async function fetchQuickStats(start, end){
    const params = new URLSearchParams();
    if(start) params.set('start', start);
    if(end) params.set('end', end);
    const resp = await fetch(`{{ url_for('admin_dashboard') }}?${params.toString()}`, {
      headers: { 'X-Partial': 'stats' }
    });
    if(!resp.ok) return;
    const html = await resp.text();
    const temp = document.createElement('div');
    temp.innerHTML = html;
    const newStats = temp.querySelector('.space-y-3');
    const oldStats = document.querySelector('#quick-stats-content');
    if(newStats && oldStats) oldStats.innerHTML = newStats.innerHTML;
  }

  document.addEventListener('DOMContentLoaded', ()=>{
    fetchSalesAndRender(currentPeriod, '', '');

    document.querySelectorAll('.period-btn').forEach(b => {
      b.addEventListener('click', ()=>{
        document.querySelectorAll('.period-btn').forEach(x => {
          x.classList.remove('btn-emerald','text-white');
          x.classList.add('btn-ghost');
        });
        b.classList.remove('btn-ghost');
        b.classList.add('btn-emerald','text-white');
        currentPeriod = b.dataset.period;
        const s = document.getElementById('filter-start').value;
        const e = document.getElementById('filter-end').value;
        fetchSalesAndRender(currentPeriod, s, e);
        fetchOrdersFilteredAndRender(s, e);
        fetchQuickStats(s, e);
      });
    });

    document.getElementById('filter-apply').addEventListener('click', ()=>{
      const s = document.getElementById('filter-start').value;
      const e = document.getElementById('filter-end').value;
      fetchSalesAndRender(currentPeriod, s, e);
      fetchOrdersFilteredAndRender(s, e);
      fetchQuickStats(s, e);
    });

    document.getElementById('filter-reset').addEventListener('click', ()=>{
      document.getElementById('filter-start').value = '';
      document.getElementById('filter-end').value = '';
      fetchSalesAndRender(currentPeriod, '', '');
      fetchOrdersFilteredAndRender('', '');
      fetchQuickStats('', '');
    });
  });
</script>
{% endblock %}
"""

_templates["order_detail.html"] = r"""
{% extends 'base.html' %}
{% block content %}
  <div class="max-w-3xl mx-auto glass p-4 sm:p-6 rounded">
    <h2 class="text-xl font-semibold mb-4">Order #{{ order.id }}</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <h3 class="font-semibold">Customer</h3>
        <div class="text-sm">{{ order.username or 'Guest' }}</div>
        <div class="text-sm">{{ order.full_name or '' }}</div>
        <div class="text-sm">{{ order.phone or '' }}</div>
      </div>
      <div>
        <h3 class="font-semibold">Order Info</h3>
        <div class="text-sm">Status: {{ order.status }}</div>
        <div class="text-sm">Placed: {{ order.created_at }}</div>
        <div class="text-sm">Total: ₹{{ '%.2f'|format(order.total) }}</div>
      </div>
    </div>

    <div class="mt-4">
      <h3 class="font-semibold">Delivery Address</h3>
      <div class="text-sm">{{ order.address }}</div>
    </div>

    <div class="mt-4">
      <h3 class="font-semibold">Items</h3>
      <ul class="list-disc pl-5 mt-2 text-sm">
        {% for it in parsed_items %}
          <li>{{ it.name }} × {{ it.qty }} — ₹{{ '%.2f'|format(it.price) }}</li>
        {% endfor %}
      </ul>
    </div>

    <div class="mt-4 flex flex-col sm:flex-row gap-2">
      <a href="{{ url_for('admin_dashboard') }}" class="px-3 py-2 rounded border text-center">Back</a>
      {% if current_user and current_user.is_admin %}
      <form method="post" action="{{ url_for('admin_update_order', order_id=order.id) }}" class="flex items-center gap-2">
        <select name="status" class="border rounded px-2 py-2 text-sm">
          <option {{ 'selected' if order.status=='Pending' else '' }}>Pending</option>
          <option {{ 'selected' if order.status=='Confirmed' else '' }}>Confirmed</option>
          <option {{ 'selected' if order.status=='Out for Delivery' else '' }}>Out for Delivery</option>
          <option {{ 'selected' if order.status=='Delivered' else '' }}>Delivered</option>
        </select>
        <button class="btn-emerald text-white px-3 py-2 rounded text-sm">Update</button>
      </form>

      <form method="post" action="{{ url_for('delete_order', order_id=order.id) }}" onsubmit="return confirm('Delete this order?');">
        <button class="text-red-600 px-3 py-2">Delete Order</button>
      </form>
      {% endif %}
    </div>
  </div>
{% endblock %}
"""

try:
    _templates  # noqa: F401
    app.jinja_loader = DictLoader(_templates)
except NameError:
    pass

# ---------- STATIC/UPLOADS ----------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_DIR'], filename)

# ---------- PRODUCT ----------
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM products WHERE id=%s;", (product_id,))
        product = cur.fetchone()
    if not product:
        flash('Product not found', 'error')
        return redirect(url_for('index'))
    return render_template('product.html', product=product)

# ---------- AUTH ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        email    = (request.form.get('email') or '').strip()
        address  = request.form.get('address') or ''
        phone    = request.form.get('phone') or ''
        if not username or not password or not email:
            flash('Username, email, and password are required', 'error')
            return render_template('register.html')

        # Validate password strength
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('register.html')

        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password, email, address, phone) VALUES (%s,%s,%s,%s,%s)",
                    (username, generate_password_hash(password), email, address, phone)
                )
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            conn.rollback()
            if getattr(e, 'pgcode', None):
                flash('Username or email may already exist', 'error')
            else:
                flash('Could not register user', 'error')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = (request.form.get('username') or '').strip()
        password   = request.form.get('password') or ''
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (identifier, identifier))
            user = cur.fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

# ---------- PROFILE ----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_conn()
    if request.method == 'POST':
        if 'avatar' not in request.files:
            flash('No file uploaded', 'error'); return redirect(url_for('profile'))
        file = request.files['avatar']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"user_{session['user_id']}_{int(datetime.utcnow().timestamp())}_{file.filename}")
            path = os.path.join(app.config['UPLOAD_DIR'], filename)
            file.save(path)
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET avatar=%s WHERE id=%s", (filename, session['user_id']))
            conn.commit()
            flash('Avatar uploaded', 'success')
            return redirect(url_for('profile'))
        flash('Invalid file', 'error')

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, username, full_name, avatar FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
    class U: pass
    u = U()
    u.id = user['id']; u.username = user['username']; u.full_name = user.get('full_name'); u.avatar = user.get('avatar')
    u.initial = (u.username[0].upper() if u.username else '?')
    return render_template('profile.html', user=u)

@app.route('/profile/remove')
@login_required
def profile_remove():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT avatar FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
    if user and user.get('avatar'):
        try: os.remove(os.path.join(app.config['UPLOAD_DIR'], user['avatar']))
        except (OSError, FileNotFoundError): pass
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET avatar=NULL WHERE id=%s", (session['user_id'],))
    conn.commit()
    flash('Avatar removed', 'success')
    return redirect(url_for('profile'))

# ---------- FORGOT PASSWORD (OTP FLOW) ----------
@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (identifier, identifier))
            user = cur.fetchone()
        if not user:
            flash('No account found with that username or email', 'error')
            return redirect(url_for('forgot_password'))

        import secrets
        otp = f"{secrets.randbelow(1000000):06d}"
        expires = datetime.utcnow() + timedelta(minutes=10)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM reset_otps WHERE user_id=%s", (user['id'],))
            cur.execute(
                "INSERT INTO reset_otps (user_id, email, otp, expires_at) VALUES (%s,%s,%s,%s)",
                (user['id'], user.get('email'), otp, expires)
            )
        conn.commit()
        ok, err = send_otp_email(user.get('email') or "", otp)
        session['reset_user'] = user['id']
        if ok:
            flash('OTP sent to your email. Please check your inbox.', 'success')
            return redirect(url_for('verify_otp'))
        flash('Failed to send OTP. Please try again later.', 'error')
        return redirect(url_for('forgot_password'))

    return render_template_string("""
    {% extends 'base.html' %}{% block content %}
    <div class="max-w-md mx-auto glass p-6 rounded shadow-lg">
      <h2 class="text-2xl font-bold text-emerald-700 mb-4 text-center">Forgot Password 🔑</h2>
      <p class="text-sm text-gray-600 text-center mb-6">Enter your registered email or username to receive an OTP</p>
      <form method="post" class="space-y-4">
        <div>
          <label class="block text-sm font-medium mb-1">Email or Username</label>
          <input name="identifier" required class="w-full border border-gray-300 rounded p-2 focus:ring-2 focus:ring-emerald-400">
        </div>
        <button class="w-full btn-emerald py-2.5 rounded-lg font-semibold shadow">Send OTP</button>
      </form>
      <div class="text-center text-sm mt-4"><a href="{{ url_for('login') }}" class="text-gray-600 hover:underline">← Back to Login</a></div>
    </div>
    {% endblock %}
    """)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_user' not in session:
        return redirect(url_for('forgot_password'))
    conn = get_conn()
    user_id = session['reset_user']
    if request.method == 'POST':
        otp = (request.form.get('otp') or '').strip()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM reset_otps WHERE user_id=%s AND otp=%s", (user_id, otp))
            rec = cur.fetchone()
        if not rec:
            flash('Invalid OTP', 'error'); return redirect(url_for('verify_otp'))
        if datetime.utcnow() > rec['expires_at']:
            with conn.cursor() as cur: cur.execute("DELETE FROM reset_otps WHERE user_id=%s", (user_id,))
            conn.commit()
            flash('OTP expired. Please request again.', 'error')
            return redirect(url_for('forgot_password'))
        with conn.cursor() as cur:
            cur.execute("UPDATE reset_otps SET verified=TRUE WHERE id=%s", (rec['id'],))
        conn.commit()
        session['otp_verified'] = True
        flash('OTP verified! You can now reset your password.', 'success')
        return redirect(url_for('reset_with_otp'))

    return render_template_string("""
    {% extends 'base.html' %}{% block content %}
    <div class="max-w-md mx-auto glass p-6 rounded shadow-lg">
      <h2 class="text-2xl font-bold text-emerald-700 mb-4 text-center">Verify OTP</h2>
      <p class="text-sm text-gray-600 text-center mb-6">Enter the 6-digit OTP sent to your email</p>
      <form method="post" class="space-y-4">
        <input name="otp" maxlength="6" class="w-full border border-gray-300 p-2 rounded text-center tracking-widest text-lg focus:ring-2 focus:ring-emerald-400" required>
        <button class="w-full btn-emerald py-2.5 rounded-lg font-semibold shadow">Verify OTP</button>
      </form>
    </div>
    {% endblock %}
    """)

@app.route('/reset_with_otp', methods=['GET', 'POST'])
def reset_with_otp():
    if not session.get('otp_verified') or 'reset_user' not in session:
        return redirect(url_for('forgot_password'))
    conn = get_conn()
    uid = session['reset_user']
    if request.method == 'POST':
        new_pass = request.form.get('password') or ''
        confirm  = request.form.get('confirm') or ''
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(new_pass)
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('reset_with_otp'))
        
        if new_pass != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_with_otp'))
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", (generate_password_hash(new_pass), uid))
            cur.execute("DELETE FROM reset_otps WHERE user_id=%s", (uid,))
        conn.commit()
        session.pop('reset_user', None); session.pop('otp_verified', None)
        flash('Password reset successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template_string("""
    {% extends 'base.html' %}{% block content %}
    <div class="max-w-md mx-auto glass p-6 rounded shadow-lg">
      <h2 class="text-2xl font-bold text-emerald-700 mb-4 text-center">Set New Password</h2>
      <p class="text-sm text-gray-600 text-center mb-6">Choose a strong password for your account</p>
      <form method="post" class="space-y-4">
        <div>
          <label class="block text-sm mb-1 font-medium">New Password</label>
          <input id="password" name="password" type="password" required class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400">
          <div id="password-strength" class="mt-1 h-2 bg-gray-200 rounded overflow-hidden">
            <div id="strength-bar" class="h-2 bg-red-400 w-0 transition-all duration-300"></div>
          </div>
          <p id="strength-text" class="text-xs text-gray-500 mt-1">Enter a strong password</p>
          
          <!-- Password Requirements Checklist -->
          <div class="mt-2 text-xs space-y-1">
            <div id="req-length" class="flex items-center gap-1 text-gray-500">
              <span class="req-icon">○</span> At least 8 characters
            </div>
            <div id="req-upper" class="flex items-center gap-1 text-gray-500">
              <span class="req-icon">○</span> One uppercase letter
            </div>
            <div id="req-lower" class="flex items-center gap-1 text-gray-500">
              <span class="req-icon">○</span> One lowercase letter
            </div>
            <div id="req-number" class="flex items-center gap-1 text-gray-500">
              <span class="req-icon">○</span> One number
            </div>
            <div id="req-special" class="flex items-center gap-1 text-gray-500">
              <span class="req-icon">○</span> One special character
            </div>
          </div>
        </div>
        <div>
          <label class="block text-sm mb-1 font-medium">Confirm Password</label>
          <input name="confirm" type="password" required class="w-full border border-gray-300 p-2 rounded focus:ring-2 focus:ring-emerald-400">
        </div>
        <button class="w-full btn-emerald py-2.5 rounded-lg font-semibold shadow">Reset Password</button>
      </form>
      
      <script>
        const passwordInput = document.getElementById('password');
        const strengthBar = document.getElementById('strength-bar');
        const strengthText = document.getElementById('strength-text');
        
        const reqLength = document.getElementById('req-length');
        const reqUpper = document.getElementById('req-upper');
        const reqLower = document.getElementById('req-lower');
        const reqNumber = document.getElementById('req-number');
        const reqSpecial = document.getElementById('req-special');

        function updateRequirement(element, met) {
          const icon = element.querySelector('.req-icon');
          if (met) {
            element.className = 'flex items-center gap-1 text-green-600';
            icon.textContent = '✓';
          } else {
            element.className = 'flex items-center gap-1 text-gray-500';
            icon.textContent = '○';
          }
        }

        passwordInput.addEventListener('input', () => {
          const val = passwordInput.value;
          let strength = 0;
          
          const hasLength = val.length >= 8;
          const hasUpper = /[A-Z]/.test(val);
          const hasLower = /[a-z]/.test(val);
          const hasNumber = /[0-9]/.test(val);
          const hasSpecial = /[^A-Za-z0-9]/.test(val);
          
          updateRequirement(reqLength, hasLength);
          updateRequirement(reqUpper, hasUpper);
          updateRequirement(reqLower, hasLower);
          updateRequirement(reqNumber, hasNumber);
          updateRequirement(reqSpecial, hasSpecial);
          
          if (hasLength) strength++;
          if (hasUpper) strength++;
          if (hasLower) strength++;
          if (hasNumber) strength++;
          if (hasSpecial) strength++;

          const percent = (strength / 5) * 100;
          strengthBar.style.width = percent + '%';

          if (strength <= 2) {
            strengthBar.className = 'h-2 bg-red-400 transition-all duration-300';
            strengthText.textContent = 'Weak password';
            strengthText.className = 'text-xs text-red-500 mt-1';
          } else if (strength === 3 || strength === 4) {
            strengthBar.className = 'h-2 bg-yellow-400 transition-all duration-300';
            strengthText.textContent = 'Medium strength';
            strengthText.className = 'text-xs text-yellow-500 mt-1';
          } else {
            strengthBar.className = 'h-2 bg-green-500 transition-all duration-300';
            strengthText.textContent = 'Strong password ✓';
            strengthText.className = 'text-xs text-green-600 mt-1';
          }
        });
      </script>
    </div>
    {% endblock %}
    """)

# ---------- CART ----------
@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    if not cart:
        return render_template('cart.html', items=[], total=0.0)

    conn = get_conn()
    items, total = [], 0.0
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        for pid_str, qty in cart.items():
            try: pid = int(pid_str)
            except ValueError: continue
            cur.execute("SELECT * FROM products WHERE id=%s", (pid,))
            p = cur.fetchone()
            if p:
                subtotal = float(p['price']) * int(qty)
                items.append({'product': p, 'qty': qty, 'subtotal': subtotal})
                total += subtotal
    return render_template('cart.html', items=items, total=total)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    try: qty = max(1, int(request.form.get('qty', 1)))
    except (ValueError, TypeError): qty = 1
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM products WHERE id=%s", (product_id,))
        p = cur.fetchone()
    if not p:
        flash('Product not found', 'error'); return redirect(url_for('index'))
    if int(p['stock']) < qty:
        flash(f"Not enough stock. Only {p['stock']} left.", 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    cart = session.get('cart', {})
    cart[str(product_id)] = cart.get(str(product_id), 0) + qty
    session['cart'] = cart
    flash('Added to cart', 'success')
    return redirect(url_for('cart'))

@app.route('/api/cart/add', methods=['POST'])
def api_cart_add():
    product_id = request.form.get('product_id', type=int)
    qty        = request.form.get('qty', type=int)
    if not product_id or not qty:
        return jsonify({'error': 'Invalid input'}), 400
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM products WHERE id=%s", (product_id,))
        product = cur.fetchone()
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    if int(product['stock']) < int(qty):
        return jsonify({'error': 'Not enough stock'}), 400
    cart = session.get('cart', {})
    cart[str(product_id)] = cart.get(str(product_id), 0) + qty
    session['cart'] = cart
    total_items = sum(cart.values())
    return jsonify({'success': True, 'product_name': product['name'], 'total_items': total_items})

@app.route('/cart/remove/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    cart.pop(str(product_id), None)
    session['cart'] = cart
    flash('Removed from cart', 'info')
    return redirect(url_for('cart'))

# ---------- CHECKOUT ----------
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash('Cart is empty', 'error'); return redirect(url_for('index'))

    conn = get_conn()
    items, total = [], 0.0
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        for pid_str, qty in cart.items():
            try: pid = int(pid_str)
            except ValueError: continue
            cur.execute("SELECT * FROM products WHERE id=%s", (pid,))
            p = cur.fetchone()
            if not p: continue
            if int(p['stock']) < int(qty):
                flash(f"Not enough stock for {p['name']}. Only {p['stock']} left.", 'error')
                return redirect(url_for('cart'))
            subtotal = float(p['price']) * int(qty)
            items.append({'product': dict(p), 'qty': int(qty), 'subtotal': subtotal})
            total += subtotal

    if request.method == 'POST':
        address = request.form.get('address') or ''
        if not address:
            flash('Address required', 'error'); return redirect(url_for('checkout'))
        order_items = [
                    {'id': it['product']['id'], 'name': it['product']['name'], 'qty': it['qty'], 'price': float(it['product']['price'])}
                    for it in items
                ]
        with conn.cursor() as cur:
                try:
                    cur.execute(
                        "INSERT INTO orders (user_id, items, total, address) VALUES (%s, %s, %s, %s) RETURNING id",
                        (session['user_id'], json.dumps(order_items), total, address)
                    )
                    res = cur.fetchone()
                    # 🧠 Handle both tuple and dict cursor results
                    if not res:
                        raise Exception("No ID returned from INSERT.")
                    order_id = res['id'] if isinstance(res, dict) else res[0]

                    # ✅ Update product stock safely
                    for it in items:
                        cur.execute(
                            "UPDATE products SET stock = stock - %s WHERE id=%s AND stock >= %s",
                            (it['qty'], it['product']['id'], it['qty'])
                        )

                    conn.commit()
                    session['cart'] = {}
                    flash(f'Order #{order_id} placed successfully. Admin will confirm delivery.', 'success')
                    return redirect(url_for('user_dashboard'))

                except Exception as e:
                    conn.rollback()
                    print("❌ Order insert failed:", e)
                    flash("Order could not be created. Please try again.", "error")
                    return redirect(url_for('checkout'))


    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
    return render_template('checkout.html', items=items, total=total, user=user)

# ---------- USER DASHBOARD ----------
@app.route('/dashboard')
@login_required
def user_dashboard():
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
        rows = cur.fetchall()
    print(f"[DEBUG user_dashboard] Found {len(rows)} orders for user {session['user_id']}")
    orders = []
    for r in rows:
        print(f"[DEBUG] Order {r['id']}: items type = {type(r['items'])}, items = {r['items'][:100] if r['items'] else 'None'}")
        parsed, summary = parse_order_items(r['items'] or '[]')
        print(f"[DEBUG] Parsed: {len(parsed)} items, summary = {summary}")
        created = to_ist_display(r['created_at'])
        orders.append({
            'id': r['id'], 'created_at': created, 'status': r['status'],
            'total': float(r['total']), 'items_parsed': parsed, 'items_summary': summary, 'address': r['address']
        })
    print(f"[DEBUG] Returning {len(orders)} orders to template")
    return render_template('dashboard_user.html', orders=orders)

@app.route('/user/stats_fragment')
@login_required
def user_stats_fragment():
    start = request.args.get('start'); end = request.args.get('end')
    conn = get_conn()
    base = "SELECT status, total FROM orders WHERE user_id=%s"
    params = [session['user_id']]
    if start and end:
        base += " AND DATE(created_at) BETWEEN %s AND %s"; params += [start, end]
    elif start:
        base += " AND DATE(created_at) >= %s"; params += [start]
    elif end:
        base += " AND DATE(created_at) <= %s"; params += [end]
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(base, params); rows = cur.fetchall()
    total_orders = len(rows)
    delivered_orders = sum(1 for r in rows if r['status'] == 'Delivered')
    total_spent = sum(float(r['total'] or 0) for r in rows)
    return f"""
      <div class='p-4 rounded-2xl bg-gradient-to-br from-emerald-50 to-white shadow-sm backdrop-blur-md border border-emerald-100'>
        <div class='text-sm text-gray-500'>Total Orders</div>
        <div class='text-2xl font-bold text-emerald-700'>{total_orders}</div>
      </div>
      <div class='p-4 rounded-2xl bg-gradient-to-br from-emerald-50 to-white shadow-sm backdrop-blur-md border border-emerald-100'>
        <div class='text-sm text-gray-500'>Delivered Orders</div>
        <div class='text-2xl font-bold text-emerald-700'>{delivered_orders}</div>
      </div>
      <div class='p-4 rounded-2xl bg-gradient-to-br from-emerald-50 to-white shadow-sm backdrop-blur-md border border-emerald-100'>
        <div class='text-sm text-gray-500'>Total Spent</div>
        <div class='text-2xl font-bold text-emerald-700'>₹{total_spent:.2f}</div>
      </div>
    """

@app.route('/user/orders_fragment')
@login_required
def user_orders_fragment():
    start = request.args.get('start'); end = request.args.get('end')
    conn = get_conn()
    base = "SELECT * FROM orders WHERE user_id=%s"
    params = [session['user_id']]
    if start and end:
        base += " AND DATE(created_at) BETWEEN %s AND %s"; params += [start, end]
    elif start:
        base += " AND DATE(created_at) >= %s"; params += [start]
    elif end:
        base += " AND DATE(created_at) <= %s"; params += [end]
    base += " ORDER BY created_at DESC"
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(base, params); rows = cur.fetchall()

    if not rows:
        return '<div class="bg-white p-6 rounded shadow">No orders yet.</div>'

    out = []
    for r in rows:
        parsed, summary = parse_order_items(r['items'] or '[]')
        created = to_ist_display(r['created_at'])
        out.append(f'''
        <div class="border rounded p-3 mb-3">
          <div class="flex justify-between items-start">
            <div>
              <div class="text-sm font-medium">Order #{r['id']} — {created}</div>
              <div class="text-xs small-muted mt-1">Status: {r['status']}</div>
              <div class="text-xs small-muted mt-1">Items: {summary}</div>
            </div>
            <div class="text-right">
              <div class="text-sm font-semibold">₹{float(r['total'] or 0):.2f}</div>
              <div class="mt-2">
                <a href="{url_for('view_order', order_id=r['id'])}" class="text-sm underline">View</a>
              </div>
            </div>
          </div>
        </div>
        ''')
    return '\n'.join(out)

# ---------- ADMIN ----------
@app.route('/admin')
@admin_required
def admin_dashboard():
    start = request.args.get('start')
    end = request.args.get('end')
    conn = get_conn()

    sql = """
        SELECT o.*, u.username
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        WHERE 1=1
    """
    params = []
    if start and end:
        sql += " AND DATE(o.created_at) BETWEEN %s AND %s"
        params += [start, end]
    elif start:
        sql += " AND DATE(o.created_at) >= %s"
        params += [start]
    elif end:
        sql += " AND DATE(o.created_at) <= %s"
        params += [end]
    sql += " ORDER BY o.created_at DESC"

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Fetch orders
        cur.execute(sql, params)
        rows = cur.fetchall()

        # Fetch all products
        cur.execute("SELECT * FROM products ORDER BY id DESC")
        products = cur.fetchall()

        # 🧩 Fetch summary stats safely
        stats_sql = """
            SELECT 
                COUNT(*) AS order_count, 
                COALESCE(SUM(total),0) AS revenue 
            FROM orders WHERE 1=1
        """
        stats_params = []
        if start and end:
            stats_sql += " AND DATE(created_at) BETWEEN %s AND %s"
            stats_params += [start, end]
        elif start:
            stats_sql += " AND DATE(created_at) >= %s"
            stats_params += [start]
        elif end:
            stats_sql += " AND DATE(created_at) <= %s"
            stats_params += [end]

        cur.execute(stats_sql, stats_params)
        stats_row = cur.fetchone() or {'order_count': 0, 'revenue': 0}
        orders_count = stats_row.get('order_count', 0)
        revenue = float(stats_row.get('revenue', 0) or 0.0)

        # 🧩 Fetch users count safely (works with RealDictCursor)
        cur.execute("SELECT COUNT(*) AS user_count FROM users")
        user_row = cur.fetchone() or {'user_count': 0}
        users_count = user_row.get('user_count', 0)

    # Group orders by day
    daywise = defaultdict(list)
    for r in rows:
        parsed, summary = parse_order_items(r['items'] or '[]')
        entry = {
            'id': r['id'],
            'user_id': r['user_id'],
            'username': r.get('username'),
            'items_parsed': parsed,
            'items_summary': summary,
            'total': float(r['total']),
            'status': r['status'],
            'created_at': to_ist_display(r['created_at']),
        }
        date_key = (
            r['created_at'].astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d')
            if isinstance(r['created_at'], datetime)
            else str(r['created_at']).split(' ')[0]
        )
        daywise[date_key].append(entry)

    stats = {'users': users_count, 'orders': orders_count, 'revenue': float(revenue or 0.0)}

    # Partial render (AJAX fragment)
    if request.headers.get('X-Partial') == 'stats':
        return render_template_string('''
        <div class="space-y-3">
          <div>Total users: <strong>{{ stats.users }}</strong></div>
          <div>Total orders: <strong>{{ stats.orders }}</strong></div>
          <div>Revenue: <strong>₹{{ '%.2f'|format(stats.revenue) }}</strong></div>
        </div>
        ''', stats=stats)

    # Full dashboard render
    return render_template('dashboard_admin.html', daywise=daywise, products=products, stats=stats)

@app.route('/admin/orders_fragment')
@admin_required
def admin_orders_fragment():
    start = request.args.get('start'); end = request.args.get('end')
    conn = get_conn()
    sql = "SELECT o.*, u.username FROM orders o LEFT JOIN users u ON o.user_id=u.id"
    params = []
    if start and end: sql += " WHERE DATE(o.created_at) BETWEEN %s AND %s"; params = [start, end]
    elif start:       sql += " WHERE DATE(o.created_at) >= %s"; params = [start]
    elif end:         sql += " WHERE DATE(o.created_at) <= %s"; params = [end]
    sql += " ORDER BY o.created_at DESC"
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params); rows = cur.fetchall()

    daywise = defaultdict(list)
    for r in rows:
        parsed, summary = parse_order_items(r['items'] or '[]')
        entry = {
            'id': r['id'], 'user_id': r['user_id'], 'username': r.get('username'),
            'items_parsed': parsed, 'items_summary': summary, 'total': float(r['total']),
            'status': r['status'], 'created_at': to_ist_display(r['created_at'])
        }
        date_key = (r['created_at'].astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d')
                    if isinstance(r['created_at'], datetime) else str(r['created_at']).split(' ')[0])
        daywise[date_key].append(entry)

    if not daywise:
        return '<div>No orders yet.</div>'

    parts = []
    for day, orders in daywise.items():
        # Reverse the orders list so oldest order gets S.No 1
        orders_reversed = list(reversed(orders))
        parts.append(f'''
        <div class="mb-6 border border-white/50 rounded-lg overflow-hidden">
          <div class="bg-emerald-50/80 px-4 py-2 text-sm font-semibold text-emerald-800 border-b border-emerald-100">
            {day} — {len(orders)} order{'s' if len(orders)>1 else ''}
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm border-collapse min-w-[720px]">
              <thead class="bg-emerald-100 text-emerald-900">
                <tr>
                  <th class="py-2 px-3 font-semibold text-center">S.No</th>
                  <th class="py-2 px-4 font-semibold text-left">Order</th>
                  <th class="py-2 px-4 font-semibold text-left">User</th>
                  <th class="py-2 px-4 font-semibold text-left">Items</th>
                  <th class="py-2 px-4 font-semibold text-right">Total</th>
                  <th class="py-2 px-4 font-semibold text-left">Status</th>
                  <th class="py-2 px-4 font-semibold text-center">Action</th>
                </tr>
              </thead>
              <tbody class="bg-white/50">
        ''')
        for idx, o in enumerate(orders_reversed, start=1):
            parts.append(f'''
                <tr class="border-t hover:bg-white/70 transition">
                  <td class="py-2 px-3 align-top text-center">
                    <div class="font-semibold text-emerald-700">{idx}</div>
                  </td>
                  <td class="py-2 px-4 align-top">
                    <div class="font-medium text-gray-800">#{o["id"]}</div>
                    <div class="text-xs text-gray-500">{o["created_at"]}</div>
                  </td>
                  <td class="py-2 px-4 align-top">{o.get("username") or ("User " + str(o["user_id"]))}</td>
                  <td class="py-2 px-4 align-top text-gray-700">{o["items_summary"]}</td>
                  <td class="py-2 px-4 align-top text-right font-semibold text-gray-800">₹{o["total"]:.2f}</td>
                  <td class="py-2 px-4 align-top">{o["status"]}</td>
                  <td class="py-2 px-4 text-center">
                    <a href="{url_for("view_order", order_id=o["id"])}" class="text-sm text-emerald-700 hover:underline">View</a>
                  </td>
                </tr>
            ''')
        parts.append('''
              </tbody>
            </table>
          </div>
        </div>
        ''')
    return '\n'.join(parts)

@app.route('/admin/sales_data')
@admin_required
def admin_sales_data():
    period = request.args.get('period', 'day')
    start = request.args.get('start'); end = request.args.get('end')
    conn = get_conn()
    base = "SELECT total, created_at FROM orders WHERE 1=1"
    params = []
    if start and end: base += " AND DATE(created_at) BETWEEN %s AND %s"; params = [start, end]
    elif start:       base += " AND DATE(created_at) >= %s"; params = [start]
    elif end:         base += " AND DATE(created_at) <= %s"; params = [end]
    base += " ORDER BY created_at ASC"
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(base, params); rows = cur.fetchall()

    data_map = OrderedDict()
    def week_key(dt):
        iso = dt.isocalendar(); return f"{iso[0]}-W{iso[1]:02d}"

    for r in rows:
        dt = r['created_at'] if isinstance(r['created_at'], datetime) else datetime.utcnow()
        if period == 'day':
            key = dt.strftime('%Y-%m-%d'); label = dt.strftime('%d %b')
        elif period == 'week':
            key = week_key(dt); monday = dt - timedelta(days=dt.weekday()); label = monday.strftime('%Y-%m-%d')
        elif period == 'month':
            key = dt.strftime('%Y-%m'); label = dt.strftime('%b %Y')
        else:
            key = dt.strftime('%Y'); label = dt.strftime('%Y')
        if key not in data_map: data_map[key] = {'label': label, 'total': 0.0}
        data_map[key]['total'] += float(r['total'] or 0)

    labels = [v['label'] for v in data_map.values()]
    values = [round(v['total'], 2) for v in data_map.values()]
    return jsonify({'labels': labels, 'values': values})

# ---------- ADMIN: ORDER ACTIONS ----------
@app.route('/admin/order/<int:order_id>')
@admin_required
def view_order_admin(order_id):
    return view_order(order_id)

@app.route('/admin/order/<int:order_id>/update', methods=['POST'])
@admin_required
def admin_update_order(order_id):
    status = request.form.get('status') or 'Pending'
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("UPDATE orders SET status=%s WHERE id=%s", (status, order_id))
    conn.commit()
    flash('Order updated', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/order/<int:order_id>/delete', methods=['POST'])
@admin_required
def delete_order(order_id):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM orders WHERE id=%s", (order_id,))
    conn.commit()
    flash('Order deleted', 'success')
    return redirect(url_for('admin_dashboard'))

# ---------- ORDER VIEW / CANCEL ----------
@app.route('/order/<int:order_id>')
@login_required
def view_order(order_id):
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT o.*, u.username, u.full_name, u.phone
            FROM orders o
            LEFT JOIN users u ON o.user_id=u.id
            WHERE o.id=%s
        """, (order_id,))
        r = cur.fetchone()
    if not r:
        flash('Order not found', 'error')
        return redirect(url_for('index'))
    parsed, _ = parse_order_items(r['items'] or '[]')
    order_obj = dict(r)
    order_obj['created_at'] = to_ist_display(r['created_at'])
    return render_template('order_detail.html', order=order_obj, parsed_items=parsed)

@app.route('/order/<int:order_id>/cancel', methods=['POST'])
@login_required
def cancel_order(order_id):
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM orders WHERE id=%s AND user_id=%s", (order_id, session['user_id']))
        r = cur.fetchone()
    if not r:
        flash('Order not found or access denied', 'error'); return redirect(url_for('user_dashboard'))
    if r['status'] != 'Pending':
        flash('Only pending orders can be cancelled', 'error'); return redirect(url_for('user_dashboard'))

    parsed, _ = parse_order_items(r['items'] or '[]')
    with conn.cursor() as cur:
        for it in parsed:
            cur.execute("UPDATE products SET stock = stock + %s WHERE id=%s", (it['qty'], it['id']))
        cur.execute("DELETE FROM orders WHERE id=%s", (order_id,))
    conn.commit()
    flash('Order cancelled and stock restored', 'success')
    return redirect(url_for('user_dashboard'))

# ---------- ADMIN: PRODUCT CRUD ----------
@app.route('/admin/product/add', methods=['GET', 'POST'])
@admin_required
def admin_add_product():
    conn = get_conn()
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        desc = request.form.get('description') or ''
        price = float(request.form.get('price') or 0)
        stock = int(request.form.get('stock') or 0)

        image_url  = (request.form.get('image_url') or '').strip()
        image_file = request.files.get('image_file')
        image_path = ''
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(f"product_{int(datetime.utcnow().timestamp())}_{image_file.filename}")
            dest = os.path.join(app.config['UPLOAD_DIR'], filename)
            image_file.save(dest)
            image_path = url_for('uploaded_file', filename=filename)
        elif image_url:
            image_path = image_url
        if not name:
            flash('Product name is required.', 'error')
            return redirect(url_for('admin_add_product'))
        with conn.cursor() as cur:
            # PostgreSQL requires %s placeholders, NOT ? placeholders
            postgres_insert_query = """
                INSERT INTO products (name, description, price, image, stock) 
                VALUES (%s, %s, %s, %s, %s)
            """
            product_data_tuple = (name, desc, price, image_path, stock)
            print(f"[DEBUG] Query: {postgres_insert_query.strip()}")
            print(f"[DEBUG] Data: {product_data_tuple}")
            cur.execute(postgres_insert_query, product_data_tuple)
        conn.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # Render add form (kept minimal since full UI is in your templates)
    return render_template_string("""
      <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><script src="https://cdn.tailwindcss.com"></script></head>
      <body class="min-h-screen flex items-center justify-center p-4" style="background:linear-gradient(180deg,#f8fafc,#fff)">
        <div class="bg-white/75 backdrop-blur p-6 rounded-xl shadow w-full max-w-md">
          <h2 class="text-2xl font-bold text-emerald-700 mb-5 text-center">Add Product</h2>
          <form method="post" enctype="multipart/form-data" class="space-y-4">
            <div><label class="block text-sm mb-1">Name</label><input name="name" required class="w-full border rounded px-3 py-2"></div>
            <div><label class="block text-sm mb-1">Description</label><textarea name="description" rows="3" class="w-full border rounded px-3 py-2"></textarea></div>
            <div><label class="block text-sm mb-1">Price (₹)</label><input name="price" type="number" step="0.01" required class="w-full border rounded px-3 py-2"></div>
            <div><label class="block text-sm mb-1">Stock</label><input name="stock" type="number" value="0" class="w-full border rounded px-3 py-2"></div>
            <div><label class="block text-sm mb-1">Image Upload (optional)</label><input type="file" name="image_file" accept="image/*" class="w-full text-sm"></div>
            <div><label class="block text-sm mb-1">or Image URL</label><input name="image_url" placeholder="https://..." class="w-full border rounded px-3 py-2"></div>
            <button class="w-full bg-emerald-600 text-white rounded py-2">Add Product</button>
            <div class="text-center mt-3"><a href="{{ url_for('admin_dashboard') }}" class="text-emerald-700 text-sm underline">← Back</a></div>
          </form>
        </div>
      </body></html>
    """)

@app.route('/admin/product/<int:product_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_product(product_id):
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM products WHERE id=%s", (product_id,))
        p = cur.fetchone()
    if not p:
        flash('Product not found', 'error'); return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        desc = request.form.get('description') or ''
        try:    price = float(request.form.get('price') or 0)
        except (ValueError, TypeError): price = 0.0
        try:    stock = int(request.form.get('stock') or 0)
        except (ValueError, TypeError): stock = 0

        image_url  = (request.form.get('image_url') or '').strip()
        image_file = request.files.get('image_file')
        image_path = p['image']
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(f"product_{product_id}_{int(datetime.utcnow().timestamp())}_{image_file.filename}")
            dest = os.path.join(app.config['UPLOAD_DIR'], filename)
            image_file.save(dest)
            image_path = url_for('uploaded_file', filename=filename)
        elif image_url:
            image_path = image_url

        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE products SET name=%s, description=%s, price=%s, image=%s, stock=%s WHERE id=%s",
                (name, desc, price, image_path, stock, product_id)
            )
        conn.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # Simple edit form (the full pretty UI remains in your templates)
    return render_template_string(f"""
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="min-h-screen flex items-center justify-center p-4" style="background:linear-gradient(180deg,#f8fafc,#fff)">
      <div class="bg-white/75 backdrop-blur p-6 rounded-xl shadow w-full max-w-md">
        <h2 class="text-2xl font-bold text-emerald-700 mb-5 text-center">Edit Product</h2>
        <form method="post" enctype="multipart/form-data" class="space-y-4">
          <div><label class="block text-sm mb-1">Name</label>
            <input name="name" value="{p['name']}" required class="w-full border rounded px-3 py-2">
          </div>
          <div><label class="block text-sm mb-1">Description</label>
            <textarea name="description" rows="3" class="w-full border rounded px-3 py-2">{p['description'] or ''}</textarea>
          </div>
          <div><label class="block text-sm mb-1">Price (₹)</label>
            <input name="price" type="number" step="0.01" value="{p['price']}" required class="w-full border rounded px-3 py-2">
          </div>
          <div><label class="block text-sm mb-1">Change Image (Upload)</label>
            <input type="file" name="image_file" accept="image/*" class="w-full text-sm">
          </div>
          <div><label class="block text-sm mb-1">or Image URL</label>
            <input name="image_url" value="{p['image'] or ''}" class="w-full border rounded px-3 py-2">
          </div>
          <div><label class="block text-sm mb-1">Stock</label>
            <input name="stock" type="number" value="{p['stock']}" class="w-full border rounded px-3 py-2">
          </div>
          <button class="w-full bg-emerald-600 text-white rounded py-2">Update Product</button>
          <div class="text-center mt-3"><a href="{{{{ url_for('admin_dashboard') }}}}" class="text-emerald-700 text-sm underline">← Back</a></div>
        </form>
      </div>
    </body></html>
    """)

@app.route('/admin/product/<int:product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
    conn.commit()
    flash('Product deleted', 'success')
    return redirect(url_for('admin_dashboard'))


# Load templates at module level (required for Vercel)
app.jinja_loader = DictLoader(_templates)

# ---------- MAIN (Local Development Only) ----------
if __name__ == '__main__':
    # This block only runs for local development (python app.py)
    # It will NOT run on Vercel serverless
    
    with app.app_context():
        init_db()

        # 🧩 Auto-create admin if not exists
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE is_admin = TRUE;")
        if cur.fetchone() is None:
            from werkzeug.security import generate_password_hash
            cur.execute("""
                INSERT INTO users (username, password, email, is_admin)
                VALUES (%s, %s, %s, %s)
            """, ("admin", generate_password_hash("admin123"), "admin@balaji.com", True))
            conn.commit()
            print("[OK] Default admin created -> username='admin', password='admin123'")
        cur.close()
    
    # Run local development server
    print("🚀 Starting local development server on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, use_reloader=False)

