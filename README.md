# VORTEX Social Network

**Database Management Systems Lab Project**  
*Sophomore Year - Computer Science/IT Engineering*

A full-stack social media platform demonstrating practical implementation of database concepts, RESTful API design, and modern web development practices with a minimal noir aesthetic.

---

## 📚 Project Overview

This project was developed as part of the Database Management Systems (DBMS) laboratory curriculum to demonstrate:
- Relational database design and normalization
- CRUD operations and complex SQL queries
- API development with database integration
- User authentication and authorization
- File handling and media storage
- Real-time data updates

---

## ✨ Features

- 🌑 **Minimal Noir Design** - Monochrome aesthetic with custom dark theme
- 💬 **Real-time Messaging** - One-on-one chat with media support (images/videos)
- 📝 **Social Feed** - Create posts with multimedia content
- 👤 **User Profiles** - Customizable avatars and user information
- 🔔 **Notifications System** - Real-time alerts for interactions
- 🔒 **Secure Authentication** - JWT-based auth with password hashing
- 🎨 **Custom UI Components** - Modal dialogs, dropdowns, and styled scrollbars

---

## 🗄️ Database Design

### Entity-Relationship Model

The application uses a **relational database** (SQLite) with the following normalized schema:

#### **Tables:**

1. **users**
   - `id` (Primary Key)
   - `username` (Unique)
   - `email` (Unique)
   - `password_hash`
   - `avatar_url`
   - `created_at`

2. **posts**
   - `id` (Primary Key)
   - `author_id` (Foreign Key → users.id)
   - `content`
   - `media_url`
   - `created_at`

3. **comments**
   - `id` (Primary Key)
   - `post_id` (Foreign Key → posts.id)
   - `author_id` (Foreign Key → users.id)
   - `content`
   - `created_at`

4. **likes**
   - `id` (Primary Key)
   - `user_id` (Foreign Key → users.id)
   - `post_id` (Foreign Key → posts.id)
   - Composite unique constraint on (user_id, post_id)

5. **messages**
   - `id` (Primary Key)
   - `sender_id` (Foreign Key → users.id)
   - `receiver_id` (Foreign Key → users.id)
   - `message`
   - `media_url`
   - `timestamp`

6. **notifications**
   - `id` (Primary Key)
   - `user_id` (Foreign Key → users.id)
   - `type` (like, comment, mention, follow)
   - `related_id`
   - `content`
   - `is_read`
   - `created_at`

### Relationships:
- **One-to-Many**: User → Posts, User → Comments, Post → Comments
- **Many-to-Many**: Users ↔ Posts (through Likes)
- **One-to-Many**: User → Messages (as sender/receiver)

---

## 🛠️ Tech Stack

### Backend
- **Python 3.x** - Programming language
- **FastAPI** - Modern web framework for APIs
- **SQLAlchemy** - ORM for database operations
- **SQLite** - Relational database
- **JWT** - Token-based authentication
- **Bcrypt** - Password hashing

### Frontend
- **Vanilla JavaScript** - No frameworks, pure JS
- **HTML5 & CSS3** - Semantic markup and modern styling
- **Fetch API** - Asynchronous HTTP requests
- **Custom CSS Variables** - Theming system

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git

### Steps

1. **Clone the repository:**
```bash
git clone https://github.com/YOUR-USERNAME/vortex-social-network.git
cd vortex-social-network
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the backend server:**
```bash
cd backend
python backapi.py
```
The API server will start at `http://127.0.0.1:8000`

4. **Open the application:**
   - Open `static/index.html` in your web browser
   - Or use a local server:
   ```bash
   # Using Python
   cd static
   python -m http.server 8080
   ```
   Then visit `http://localhost:8080`

5. **Create an account:**
   - Register with email and password
   - Start using the platform!

---

## 📁 Project Structure

```
VORTEX/
├── backend/
│   ├── backapi.py                  # FastAPI application & database models
│   ├── schema.db                   # SQLite database (auto-generated)
│   ├── migration_add_media_support.sql
│   └── uploads/                    # User-uploaded media
├── static/
│   ├── index.html                  # Login/signup page
│   ├── noir-feed.html              # Main feed
│   ├── noir-chat.html              # Messaging interface
│   ├── noir-profile.html           # User's own profile
│   ├── noir-public-profile.html    # View other users
│   ├── noir-notifications.html     # Notifications page
│   ├── noir-feed-style.css         # Shared styles for feed/profile
│   ├── noir-chat-style.css         # Chat-specific styles
│   └── style.css                   # Login page styles
├── requirements.txt                # Python dependencies
├── .gitignore                      # Git ignore rules
└── README.md                       # This file
```

---

## 🔌 API Endpoints

### Authentication
- `POST /register` - Create new user account
- `POST /login` - Login and receive JWT token

### Users
- `GET /users/me` - Get current user info
- `PUT /users/me` - Update username
- `POST /users/me/avatar` - Upload profile picture
- `GET /users/search?q={query}` - Search users

### Posts
- `GET /posts` - Get feed posts (paginated)
- `POST /posts` - Create new post
- `DELETE /posts/{id}` - Delete own post
- `POST /posts/{id}/like` - Like a post
- `DELETE /posts/{id}/like` - Unlike a post
- `POST /posts/{id}/comments` - Add comment
- `DELETE /comments/{id}` - Delete comment

### Messages
- `GET /messages/conversations` - Get all conversations
- `GET /messages/{user_id}` - Get messages with specific user
- `POST /messages` - Send message
- `PUT /messages/{id}` - Edit message (text only)
- `DELETE /messages/{id}` - Delete message
- `DELETE /messages/conversation/{user_id}` - Clear conversation

### Notifications
- `GET /notifications` - Get user notifications
- `PUT /notifications/{id}/read` - Mark as read
- `PUT /notifications/read-all` - Mark all as read

---

## 💡 Database Concepts Demonstrated

### 1. **CRUD Operations**
   - Create: User registration, posting, messaging
   - Read: Feed queries, user profiles, conversations
   - Update: Edit profile, edit messages
   - Delete: Delete posts, messages, conversations

### 2. **Joins & Complex Queries**
   - Join users with posts for feed display
   - Join posts with likes and comments counts
   - Aggregate functions for statistics

### 3. **Constraints**
   - Primary keys on all tables
   - Foreign key relationships
   - Unique constraints (email, username)
   - Composite unique constraint (user_id, post_id in likes)

### 4. **Transactions**
   - Atomic operations for likes
   - Message sending with notification creation

### 5. **Indexing** (Implicit via SQLAlchemy)
   - Primary key indexes
   - Foreign key indexes
   - Unique constraint indexes

### 6. **Authentication & Security**
   - Password hashing using bcrypt
   - JWT token-based authentication
   - SQL injection prevention via ORM

---

## 🎨 Design System

### Color Palette
```css
--noir-black: #000000      /* Background */
--noir-darker: #0a0a0a     /* Elevated surfaces */
--noir-dark: #171717       /* Cards, inputs */
--noir-medium: #262626     /* Hover states */
--noir-gray: #404040       /* Borders, scrollbar */
--noir-light-gray: #525252 /* Active borders */
--noir-muted: #737373      /* Secondary text */
--noir-text: #e5e5e5       /* Primary text */
--noir-white: #ffffff      /* Accents, buttons */
```

### Typography
- **Font Family:** Inter (Google Fonts)
- **Weights:** 300 (light), 400 (regular), 500 (medium), 600 (semibold)
- **Sizes:** 0.75rem to 1.5rem

---

## 📝 Key Learning Outcomes

1. ✅ Designed and implemented a normalized relational database
2. ✅ Developed RESTful API with proper HTTP methods and status codes
3. ✅ Implemented user authentication and authorization
4. ✅ Handled file uploads and media storage
5. ✅ Created responsive UI without frameworks
6. ✅ Applied security best practices (password hashing, JWT)
7. ✅ Managed database migrations and schema changes
8. ✅ Implemented real-time-like features with polling

---

## 🔒 Security Features

- **Password Hashing:** Bcrypt with salt
- **JWT Authentication:** Token-based auth for API
- **Input Validation:** Pydantic models for request validation
- **SQL Injection Prevention:** SQLAlchemy ORM parameterized queries
- **File Upload Validation:** Type and size restrictions
- **CORS Configuration:** Controlled cross-origin requests

---

## 🚧 Future Enhancements

- [ ] WebSocket integration for real-time messaging
- [ ] PostgreSQL for production deployment
- [ ] Image compression and optimization
- [ ] Advanced search with full-text indexing
- [ ] User blocking and reporting
- [ ] Dark/light theme toggle
- [ ] Mobile responsive design improvements
- [ ] Unit and integration tests

---

## 📄 License

MIT License - Free for educational and personal use.

---

## 👨‍💻 Author

**Sophomore Student - DBMS Lab Project**  
*Computer Science/IT Engineering*

---

## 🙏 Acknowledgments

- Database design concepts from DBMS coursework
- FastAPI documentation and community
- Modern web development best practices

---

## 📧 Contact

For questions about this project, please open an issue on GitHub or contact through your institution's email.
