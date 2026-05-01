import sqlite3

conn = sqlite3.connect("smartcart.db")
cursor = conn.cursor()

# USERS TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    profile_image TEXT
)
""")

# ADMIN TABLE (important)
cursor.execute("""
CREATE TABLE IF NOT EXISTS admin (
    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    password TEXT,
    profile_image TEXT
)
""")

# PRODUCTS TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS products (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    category TEXT,
    price REAL,
    original_price REAL,
    image TEXT,
    admin_id INTEGER
)
""")

# CART TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS cart (
    cart_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    name TEXT,
    price REAL,
    image TEXT,
    quantity INTEGER
)
""")

# ORDERS TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS orders (
    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    razorpay_order_id TEXT,
    razorpay_payment_id TEXT,
    amount REAL,
    payment_status TEXT,
    order_status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# ORDER ITEMS TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER,
    product_id INTEGER,
    product_name TEXT,
    quantity INTEGER,
    price REAL
)
""")

# ADDRESS TABLE
cursor.execute("""
CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    address TEXT,
    city TEXT,
    pincode TEXT
)
""")

conn.commit()
conn.close()

print("All tables created successfully!")