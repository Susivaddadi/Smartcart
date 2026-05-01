from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
import razorpay
from flask import request, jsonify, render_template
import traceback
from flask import make_response, render_template
from utils.pdf_generator import generate_pdf
import smtplib
from email.mime.text import MIMEText


app = Flask(__name__)
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)
app.secret_key = config.SECRET_KEY
app.config['USERS_UPLOAD_FOLDER'] = 'static/uploads/profile_images'
os.makedirs(app.config['USERS_UPLOAD_FOLDER'], exist_ok=True)

serializer = URLSafeTimedSerializer(app.secret_key)
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_USERNAME

mail = Mail(app)

# -------------------- DB CONNECTION --------------------
def get_db_connection():
    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-register', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    # check email already exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-register')

    # store temp data
    session['signup_name'] = name
    session['signup_email'] = email

    # generate OTP
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # send email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')

# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # 🔥 FIX: decode added
    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')

# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    stored_hashed_password = admin['password']

    if isinstance(stored_hashed_password, str):
        stored_hashed_password = stored_hashed_password.encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    #flash("Login Successful!", "success")
    return redirect('/admin-dashboard')
#==================================================================
# forgot paaword route
#==================================================================
@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        # Generate token
        token = serializer.dumps(email, salt='reset-password')

        # Correct link (HTTP only)
        reset_link = url_for(
            'reset_password',
            token=token,
            _external=True
        )

        # Send mail
        msg = Message(
            subject="Reset Password",
            recipients=[email]
        )
        msg.body = f"Click this link to reset your password:\n\n{reset_link}"

        try:
            mail.send(msg)
            flash("Reset link sent to your email!", "success")
        except Exception as e:
            flash(str(e), "danger")

        return redirect('/admin/forgot-password')

    return render_template('admin/forgot_password.html')
#=============================================================
#reset_password
#===============================================================
@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=600)
    except:
        flash("Invalid or expired link", "danger")
        return redirect('/admin/forgot-password')

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(request.url)

        hashed = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE admin SET password=? WHERE email=?",
            (hashed, email)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect(url_for('admin_login'))

    return render_template('admin/reset_password.html')

# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])



# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')

# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")



# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = float(request.form['price'])
    original_price = float(request.form.get('original_price') or request.form['price'])

    if price >= 1000:
        coins = 100
    elif price >= 500:
        coins = 50
    else:
        coins = 0

    image_file = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO products 
        (name, description, category, original_price, price, image, admin_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (name, description, category, original_price, price, filename, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')

# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# ===============================================================

#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)
# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)
# =================================================================
# ROUTE-12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    if new_image and new_image.filename != "":
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    cursor.execute("""
        UPDATE products
        SET name=?, description=?, category=?, price=?, image=?
        WHERE product_id=? AND admin_id=?
    """, (name, description, category, price, final_image_name, item_id, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE: PRODUCT LIST WITH SEARCH + CATEGORY FILTER (SQLITE)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT category 
        FROM products
        WHERE admin_id = ?
    """, (admin_id,))
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE admin_id = ?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )
# =================================================================
# ROUTE 14: DELETE PRODUCT
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT image FROM products 
        WHERE product_id=? AND admin_id=?
    """, (item_id, admin_id))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    cursor.execute("""
        DELETE FROM products 
        WHERE product_id=? AND admin_id=?
    """, (item_id, admin_id))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')


#==========================================================
# add admin profile
#==========================================================
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER


@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

# =================================================================
# ROUTE 2: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')
# =================================================================
# ROUTE: USER REGISTRATION
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/')
#=========================login============================
@app.route('/', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/')

    stored_password = user['password']

    # 🔥 Fix for both cases (bytes / string)
    if isinstance(stored_password, str):
        stored_password = stored_password.encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        flash("Incorrect password!", "danger")
        return redirect('/')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')
# =================================================================
# ROUTE: USER DASHBOARD
# =================================================================
#@app.route('/user-dashboard')
#def user_dashboard():

 #   if 'user_id' not in session:
 #       flash("Please login first!", "danger")
 #       return redirect('/user-login')

   # return render_template("user/user_home.html", user_name=session['user_name'])
   
@app.route('/user/forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        token = serializer.dumps(email, salt='reset-password')

        reset_link = url_for(
            'user_reset_password',
            token=token,
            _external=True
        )

        msg = Message(
            subject="Reset Password",
            recipients=[email]
        )
        msg.body = f"Click this link to reset your password:\n\n{reset_link}"

        try:
            mail.send(msg)
            flash("Reset link sent to your email!", "success")
        except Exception as e:
            flash(str(e), "danger")

        return redirect('/user/forgot-password')

    return render_template('user/forgot_password.html')

#==================reset======================
@app.route('/user/reset-password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt='reset-password',
            max_age=600
        )
    except:
        flash("Invalid or expired link", "danger")
        return redirect(url_for('user_forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(request.url)

        hashed = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password=? WHERE email=?",
            (hashed, email)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully! Please login.", "success")
        return redirect(url_for('user_login'))

    return render_template('user/reset_password.html')
#===============dashboard=======================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    user_id = session.get('user_id')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Cart count from DB
    cursor.execute("""
        SELECT SUM(quantity) AS cart_count
        FROM cart
        WHERE user_id = ?
    """, (user_id,))
    cart_data = cursor.fetchone()

    cart_count = cart_data['cart_count'] if cart_data and cart_data['cart_count'] else 0

    # Categories
    cursor.execute("""
        SELECT DISTINCT category
        FROM products
        WHERE category IS NOT NULL
        AND category != ''
        ORDER BY category ASC
    """)
    categories = cursor.fetchall()

    # Saved amount
    cursor.execute("""
        SELECT 
            SUM((p.original_price - p.price) * c.quantity) AS saved_amount
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
        AND p.original_price > p.price
    """, (user_id,))
    saved = cursor.fetchone()

    saved_amount = saved['saved_amount'] if saved and saved['saved_amount'] else 0

    cursor.close()
    conn.close()

    member_since = "2026"

    return render_template(
        "user/user_home.html",
        user_name=session.get('user_name', 'User'),
        cart_count=cart_count,
        saved_amount=saved_amount,
        member_since=member_since,
        categories=categories
    )


# =================================================================
# ROUTE: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/')
# =================================================================
# ROUTE: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)
# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check product exists
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    # Check already in cart
    cursor.execute("""
        SELECT * FROM cart
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    cart_item = cursor.fetchone()

    if cart_item:
        cursor.execute("""
            UPDATE cart
            SET quantity = quantity + 1
            WHERE user_id=? AND product_id=?
        """, (user_id, product_id))
    else:
        cursor.execute("""
            INSERT INTO cart (user_id, product_id, name, price, image, quantity)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            product_id,
            product['name'],
            product['price'],
            product['image'],
            1
        ))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item added to cart!", "success")
    return redirect(request.referrer)


# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            c.product_id,
            c.quantity,
            p.name,
            p.price,
            p.image
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id=?
    """, (user_id,))

    items = cursor.fetchall()

    cursor.close()
    conn.close()

    cart = {}

    for item in items:
        pid = str(item['product_id'])
        cart[pid] = {
            'name': item['name'],
            'price': float(item['price']),
            'image': item['image'],
            'quantity': item['quantity']
        }

    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)
# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    if 'user_id' not in session:
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cart
        SET quantity = quantity + 1
        WHERE user_id=? AND product_id=?
    """, (user_id, pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')


@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    if 'user_id' not in session:
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT quantity FROM cart
        WHERE user_id=? AND product_id=?
    """, (user_id, pid))

    item = cursor.fetchone()

    if item:
        if item['quantity'] > 1:
            cursor.execute("""
                UPDATE cart
                SET quantity = quantity - 1
                WHERE user_id=? AND product_id=?
            """, (user_id, pid))
        else:
            cursor.execute("""
                DELETE FROM cart
                WHERE user_id=? AND product_id=?
            """, (user_id, pid))

        conn.commit()

    cursor.close()
    conn.close()

    return redirect('/user/cart')


@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    if 'user_id' not in session:
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM cart
        WHERE user_id=? AND product_id=?
    """, (user_id, pid))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item removed!", "success")
    return redirect('/user/cart')


USERS_UPLOAD_FOLDER = 'static/uploads/user_profiles'
app.config['USERS_UPLOAD_FOLDER'] = USERS_UPLOAD_FOLDER

# ==========================================================
# USER PROFILE SHOW + UPDATE
# ==========================================================
@app.route('/user-profile', methods=['GET', 'POST'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password', '')
        profile_image = request.files.get('profile_image')

        cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
        user = cursor.fetchone()

        old_image = user['profile_image'] if user['profile_image'] else ''

        if password:
            hashed_password = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
        else:
            hashed_password = user['password']

        if profile_image and profile_image.filename != "":
            from werkzeug.utils import secure_filename
            import os

            filename = secure_filename(profile_image.filename)

            save_path = os.path.join(
                app.config['USERS_UPLOAD_FOLDER'],
                filename
            )

            profile_image.save(save_path)
            final_image = filename
        else:
            final_image = old_image

        cursor.execute("""
            UPDATE users
            SET name=?, email=?, password=?, profile_image=?
            WHERE user_id=?
        """, (name, email, hashed_password, final_image, user_id))

        conn.commit()

        session['user_name'] = name
        session['user_email'] = email

        cursor.close()
        conn.close()

        flash("Profile updated successfully!", "success")
        return redirect('/user-profile')

    cursor.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('user/user_profile.html', user=user)


@app.route('/user/profile')
def user_profile_redirect():
    return redirect('/user-profile')
# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            c.quantity,
            p.price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id=?
    """, (user_id,))
    cart_items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not cart_items:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    total_amount = sum(item['price'] * item['quantity'] for item in cart_items)
    razorpay_amount = int(total_amount * 100)

    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )
# ================= ADD ADDRESS =================
@app.route('/add-address', methods=['GET', 'POST'])
def add_address():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        city = request.form['city']
        pincode = request.form['pincode']

        cursor.execute("SELECT * FROM addresses WHERE user_id=?", (user_id,))
        old_address = cursor.fetchone()

        if old_address:
            cursor.execute("""
                UPDATE addresses
                SET name=?, address=?, city=?, pincode=?
                WHERE user_id=?
            """, (name, address, city, pincode, user_id))
        else:
            cursor.execute("""
                INSERT INTO addresses (user_id, name, address, city, pincode)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, name, address, city, pincode))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Address saved successfully!", "success")
        return redirect('/add-address')

    cursor.execute("SELECT * FROM addresses WHERE user_id=?", (user_id,))
    addresses = cursor.fetchone()

    if not addresses:
        addresses = {
            'name': '',
            'address': '',
            'city': '',
            'pincode': ''
        }

    cursor.close()
    conn.close()

    return render_template('user/add_address.html', addresses=addresses)
# ================= EDIT ADDRESS =================
@app.route('/edit_address', methods=['GET', 'POST'])
def edit_address():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'GET':
        cursor.execute(
            "SELECT * FROM addresses WHERE user_id=?",
            (user_id,)
        )
        addresses = cursor.fetchone()

        cursor.close()
        conn.close()

        return render_template(
            'user/edit_address.html',
            addresses=addresses
        )

    name = request.form['name']
    address = request.form['address']
    city = request.form['city']
    pincode = request.form['pincode']

    cursor.execute("""
        UPDATE addresses
        SET name=?,
            address=?,
            city=?,
            pincode=?
        WHERE user_id=?
    """, (name, address, city, pincode, user_id))

    conn.commit()

    cursor.close()
    conn.close()

    flash("Address updated successfully!", "success")
    return redirect('/add-address')


@app.route('/delete-address/<int:address_id>')
def delete_address(address_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM addresses WHERE id=? AND user_id=?",
        (address_id, session['user_id'])
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Address deleted successfully!", "success")
    return redirect('/add-address')

# ================= CONTINUE TO PAYMENT =================
@app.route('/continue-payment/<int:address_id>', methods=['GET', 'POST'])
def continue_payment(address_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    session['address_id'] = address_id

    return redirect('/payment')


@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']
    selected_products = session.get('selected_products', [])

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if selected_products:
            selected_products = [int(pid) for pid in selected_products]
            placeholders = ",".join(["?"] * len(selected_products))

            cursor.execute(f"""
                SELECT 
                    c.product_id,
                    c.quantity,
                    p.name,
                    p.price
                FROM cart c
                JOIN products p ON c.product_id = p.product_id
                WHERE c.user_id = ?
                AND c.product_id IN ({placeholders})
            """, [user_id] + selected_products)
        else:
            cursor.execute("""
                SELECT 
                    c.product_id,
                    c.quantity,
                    p.name,
                    p.price
                FROM cart c
                JOIN products p ON c.product_id = p.product_id
                WHERE c.user_id = ?
            """, (user_id,))

        cart_items = cursor.fetchall()

        if not cart_items:
            flash("Cart is empty. Cannot create order.", "danger")
            return redirect('/user/products')

        total_amount = sum(item['price'] * item['quantity'] for item in cart_items)

        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))

        order_db_id = cursor.lastrowid

        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (
                order_db_id,
                item['product_id'],
                item['name'],
                item['quantity'],
                item['price']
            ))

        product_ids = [item['product_id'] for item in cart_items]
        placeholders = ",".join(["?"] * len(product_ids))

        cursor.execute(f"""
            DELETE FROM cart
            WHERE user_id = ?
            AND product_id IN ({placeholders})
        """, [user_id] + product_ids)

        conn.commit()

        session.pop('selected_products', None)
        session.pop('razorpay_order_id', None)

        ##flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()

#================================================================
# Orders Success
#===============================================================
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM orders
        WHERE order_id=? AND user_id=?
    """, (order_db_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/products')

    cursor.execute("""
        SELECT *
        FROM order_items
        WHERE order_id=?
    """, (order_db_id,))
    items = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM addresses
        WHERE user_id=?
        LIMIT 1
    """, (session['user_id'],))
    address = cursor.fetchone()

    if not address:
        address = {
            "name": "",
            "address": "",
            "city": "",
            "pincode": ""
        }

    cursor.close()
    conn.close()

    return render_template(
        "user/order_success.html",
        order=order,
        items=items,
        address=address
    )


@app.route('/user/my-orders')
def User_my_orders():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            order_id,
            razorpay_order_id,
            amount,
            payment_status,
            created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY order_id DESC
    """, (session['user_id'],))

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user/my_orders.html', orders=orders)


# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch order
    cursor.execute("""
        SELECT *
        FROM orders
        WHERE order_id=? AND user_id=?
    """, (order_id, session['user_id']))

    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Fetch order items
    cursor.execute("""
        SELECT *
        FROM order_items
        WHERE order_id=?
    """, (order_id,))

    items = cursor.fetchall()

    # Fetch address
    cursor.execute("""
        SELECT *
        FROM addresses
        WHERE user_id=?
        LIMIT 1
    """, (session['user_id'],))

    address = cursor.fetchone()

    if not address:
        address = {
            "name": "",
            "address": "",
            "city": "",
            "pincode": ""
        }

    cursor.close()
    conn.close()

    html = render_template(
        "user/invoice.html",
        order=order,
        items=items,
        address=address
    )

    pdf = generate_pdf(html)

    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response


@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login as admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.order_id, o.user_id, o.amount, 
               o.payment_status, o.order_status, o.created_at,
               u.name AS username
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
    """)

    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/order_list.html", orders=orders)

# ADMIN: VIEW ORDER DETAILS
# ================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    # Login check
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # DB connection
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row   # important for dict access
    cursor = conn.cursor()

    # Get order details
    cursor.execute("""
        SELECT *
        FROM orders
        WHERE order_id = ?
    """, (order_id,))
    order = cursor.fetchone()

    # Get order items
    cursor.execute("""
        SELECT *
        FROM order_items
        WHERE order_id = ?
    """, (order_id,))
    items = cursor.fetchall()

    # Close connection
    cursor.close()
    conn.close()

    # Render page
    return render_template(
        "admin/order_details.html",
        order=order,
        items=items
    )
    
    
@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE orders SET order_status=? WHERE order_id=?",
        (new_status, order_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")


@app.route('/cart/select-items', methods=['POST'])
def select_cart_items():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    selected_products = request.form.getlist('selected_products')

    if not selected_products:
        flash("Please select at least one product!", "warning")
        return redirect('/user/cart')

    session['selected_products'] = selected_products

    return redirect('/add-address')

@app.route('/payment')
def payment():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    user_id = session['user_id']

    selected_products = session.get('selected_products', [])

    if not selected_products:
        flash("Please select at least one product!", "warning")
        return redirect('/user/cart')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM addresses WHERE user_id=?", (user_id,))
    addresses = cursor.fetchone()

    if not addresses:
        cursor.close()
        conn.close()
        flash("Please add delivery address first!", "danger")
        return redirect('/add-address')

    selected_products = [int(pid) for pid in selected_products]
    placeholders = ",".join(["?"] * len(selected_products))

    cursor.execute(f"""
        SELECT 
            c.quantity,
            p.price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
        AND c.product_id IN ({placeholders})
    """, [user_id] + selected_products)

    cart_items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not cart_items:
        flash("Selected products not found!", "danger")
        return redirect('/user/cart')

    grand_total = sum(float(item['price']) * int(item['quantity']) for item in cart_items)

    if grand_total <= 0:
        flash("Selected products not found!", "danger")
        return redirect('/user/cart')

    razorpay_order = razorpay_client.order.create({
        "amount": int(grand_total * 100),
        "currency": "INR",
        "payment_capture": 1
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        'user/payment.html',
        grand_total=grand_total,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id'],
        addresses=addresses
    )


@app.route('/about')
def about():
    return render_template("user/about.html")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        sender_email = "susivaddadi07@gmail.com"
        sender_password = "turm idnl xlzb ppwv"
        receiver_email = "vaddadisusi483@gmail.com"

        body = f"""
Name: {name}
Email: {email}

Message:
{message}
"""

        msg = MIMEText(body)
        msg['Subject'] = "SmartCart Contact Query"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()

        flash("Your message sent successfully!")
        return redirect('/contact')

    return render_template("user/contact.html")


if __name__ == "__main__":
    app.run(debug=True)