# SecureVault — SWE210 Software Security Group Project

A secure web application built with Flask that demonstrates **Authentication**, **Access Control (RBAC)**, and **Encryption**.

---

## How to Run

### 1. Install Python
Make sure Python 3.8+ is installed: https://python.org

### 2. Install Dependencies
Open a terminal in the project folder and run:

```
pip install -r requirements.txt
```

### 3. Run the App
```
python app.py
```

The server will start at **http://127.0.0.1:5000**

### 4. Default Admin Account
On first run, a default admin is created automatically:
- **Username:** `admin`
- **Password:** `admin123`

You can register new users through the app — they get the "user" role by default. The admin can promote/demote users from the Admin Panel.

---

## Project Structure

```
secure-app/
├── app.py              # Main application (all routes + logic)
├── requirements.txt    # Python dependencies
├── secret.key          # Fernet encryption key (auto-generated)
├── database.db         # SQLite database (auto-created)
├── templates/
│   ├── base.html       # Base layout with nav + styling
│   ├── login.html      # Login page
│   ├── register.html   # Registration page
│   ├── dashboard.html  # User dashboard (add/view secrets)
│   ├── admin.html      # Admin panel (user management)
│   ├── 403.html        # Access Denied error page
│   └── 404.html        # Not Found error page
└── README.md
```

---

## Security Features

### 1. Authentication
- User registration with username + password
- Passwords hashed with **bcrypt** (includes automatic salting)
- No plaintext passwords stored — only bcrypt hashes
- Session management via Flask-Login

### 2. Access Control (RBAC)
- Two roles: **Admin** and **User**
- Admin-only pages protected with custom `@admin_required` decorator
- Unauthorized users receive **HTTP 403 Forbidden**
- Admin can promote users to admin or demote other admins

### 3. Encryption
- Sensitive user data (secrets/notes) encrypted before database storage
- Uses **Fernet symmetric encryption** (AES-128-CBC + HMAC-SHA256)
- Encryption key stored in `secret.key` file
- Data decrypted only when displayed to the authenticated owner

---

## Test Scenarios for Screenshots

1. **Register** a new user → screenshot the form + success message
2. **Login** with the new user → screenshot the login page
3. **Add a secret** → screenshot showing the decrypted content + encrypted ciphertext
4. **Try accessing /admin as a regular user** → screenshot the 403 Forbidden page
5. **Login as admin** → screenshot the Admin Panel with user list + stats
6. **Promote a user** → screenshot before/after showing role change

---

## Team Contribution Split (Suggestion)

| Member   | Responsibility                          |
|----------|-----------------------------------------|
| Member 1 | Authentication (register, login, hashing) |
| Member 2 | Access Control (RBAC, admin panel, decorator) |
| Member 3 | Encryption (Fernet, encrypt/decrypt, secrets) |
| Everyone | Report sections + presentation slides    |
