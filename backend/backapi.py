from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, DateTime, text, Boolean, inspect
from sqlalchemy.orm import sessionmaker, Session, declarative_base, Mapped, mapped_column
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import os
import shutil
import json
import re
from pathlib import Path
import bcrypt
from dotenv import load_dotenv
from collections import defaultdict

# Ensure newer passlib releases can read the version from bcrypt>=4
if not hasattr(bcrypt, "__about__"):
    class _BcryptAbout:
        __version__ = getattr(bcrypt, "__version__", "unknown")

    bcrypt.__about__ = _BcryptAbout()

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set.")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_for_development")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    bio = Column(String(500), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    allow_mentions = Column(Boolean, nullable=False, server_default=text("1"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class BlogPost(Base):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    title = Column(String(255), nullable=False)
    content = Column(String(10000), nullable=False)
    media_url = Column(String(500), nullable=True)
    repost_of = Column(Integer, nullable=True)  # ID of original post if this is a repost
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)
    parent_comment_id = Column(Integer, nullable=True)  # For replies to comments
    content = Column(String(1000), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, nullable=False)
    receiver_id = Column(Integer, nullable=False)
    message = Column(String(1000), nullable=True)
    media_url = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    read_status = Column(Integer, default=0)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    reporter_id = Column(Integer, nullable=False)
    report_type = Column(String(50), nullable=False)  # 'user' or 'message' or 'post'
    target_id = Column(Integer, nullable=False)
    reason = Column(String(100), nullable=False)
    details = Column(String(1000), nullable=True)
    status = Column(String(50), default="pending")  # pending, reviewed, resolved
    created_at = Column(DateTime, default=datetime.utcnow)

class BlockedUser(Base):
    __tablename__ = "blocked_users"
    id = Column(Integer, primary_key=True, index=True)
    blocker_id = Column(Integer, nullable=False)
    blocked_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Like(Base):
    __tablename__ = "likes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    post_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Repost(Base):
    __tablename__ = "reposts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    post_id = Column(Integer, nullable=False)
    quote_text = Column(String(500), nullable=True)  # For quote retweets
    created_at = Column(DateTime, default=datetime.utcnow)

class Bookmark(Base):
    __tablename__ = "bookmarks"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    post_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Follow(Base):
    __tablename__ = "follows"
    id = Column(Integer, primary_key=True, index=True)
    follower_id = Column(Integer, nullable=False)
    following_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    type = Column(String(50), nullable=False)  # like, comment, follow, mention, repost
    from_user_id = Column(Integer, nullable=False)
    post_id = Column(Integer, nullable=True)
    comment_id = Column(Integer, nullable=True)
    message = Column(String(500), nullable=True)
    read_status = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class Mention(Base):
    __tablename__ = "mentions"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, nullable=True)
    comment_id = Column(Integer, nullable=True)
    message_id = Column(Integer, nullable=True)
    mentioned_user_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Poll(Base):
    __tablename__ = "polls"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, nullable=False)
    question = Column(String(500), nullable=False)
    options = Column(String(2000), nullable=False)  # JSON string of options
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class PollVote(Base):
    __tablename__ = "poll_votes"
    id = Column(Integer, primary_key=True, index=True)
    poll_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)
    option_index = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserUpdate(BaseModel):
    username: Optional[str] = None
    full_name: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = None
    allow_mentions: Optional[bool] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    allow_mentions: bool = True
    created_at: datetime
    
    class Config:
        from_attributes = True

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class BlogPostCreate(BaseModel):
    title: str
    content: str

class BlogPostUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None

class BlogPostResponse(BaseModel):
    id: int
    user_id: int
    title: str
    content: str
    media_url: Optional[str] = None
    repost_of: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    author_username: Optional[str] = None
    author_avatar_url: Optional[str] = None
    like_count: Optional[int] = 0
    comment_count: Optional[int] = 0
    repost_count: Optional[int] = 0
    is_liked: Optional[bool] = False
    is_reposted: Optional[bool] = False
    is_bookmarked: Optional[bool] = False
    
    class Config:
        from_attributes = True

class CommentCreate(BaseModel):
    content: str
    parent_comment_id: Optional[int] = None

class CommentResponse(BaseModel):
    id: int
    post_id: int
    user_id: int
    parent_comment_id: Optional[int] = None
    parent_username: Optional[str] = None
    content: str
    created_at: datetime
    author_username: Optional[str] = None
    author_avatar_url: Optional[str] = None
    like_count: Optional[int] = 0
    reply_count: Optional[int] = 0
    
    class Config:
        from_attributes = True

class ReportCreate(BaseModel):
    report_type: str  # 'user', 'message', or 'post'
    target_id: int
    reason: str
    details: Optional[str] = None

class ReportResponse(BaseModel):
    id: int
    reporter_id: int
    report_type: str
    target_id: int
    reason: str
    details: Optional[str] = None
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class MessageUpdate(BaseModel):
    message: str

class MessageCreate(BaseModel):
    receiver_id: int
    message: Optional[str] = None

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    message: Optional[str] = None
    media_url: Optional[str] = None
    timestamp: datetime
    read_status: bool
    sender_username: Optional[str] = None
    receiver_username: Optional[str] = None
    
    class Config:
        from_attributes = True

class NotificationResponse(BaseModel):
    id: int
    user_id: int
    type: str
    from_user_id: int
    post_id: Optional[int] = None
    comment_id: Optional[int] = None
    message: Optional[str] = None
    read_status: int
    created_at: datetime
    from_username: Optional[str] = None
    from_avatar_url: Optional[str] = None
    
    class Config:
        from_attributes = True

class PollCreate(BaseModel):
    question: str
    options: List[str]
    hours: Optional[int] = 24

class PollResponse(BaseModel):
    id: int
    post_id: int
    question: str
    options: List[str]
    votes: List[int]
    total_votes: int
    user_voted: Optional[int] = None
    expires_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class RepostCreate(BaseModel):
    post_id: int
    quote_text: Optional[str] = None


def ensure_schema():
    """Backfill columns that may be missing in existing databases."""
    try:
        with engine.begin() as connection:
            inspector = inspect(connection)
            user_columns = {column["name"] for column in inspector.get_columns("users")}
            if "allow_mentions" not in user_columns:
                connection.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN allow_mentions TINYINT(1) NOT NULL DEFAULT 1"
                    )
                )
    except Exception as exc:  # pragma: no cover - defensive safety net
        print(f"[schema] Unable to ensure allow_mentions column: {exc}")

# Create uploads directory
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
(UPLOAD_DIR / "avatars").mkdir(exist_ok=True)
(UPLOAD_DIR / "posts").mkdir(exist_ok=True)
(UPLOAD_DIR / "messages").mkdir(exist_ok=True)

app = FastAPI()

ensure_schema()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for uploads
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

def save_upload_file(upload_file: UploadFile, destination: Path) -> str:
    """Save uploaded file and return the URL path"""
    try:
        with destination.open("wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        return f"/uploads/{destination.relative_to(UPLOAD_DIR)}"
    finally:
        upload_file.file.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user

@app.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user_email = get_user_by_email(db, email=user.email)
    if db_user_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    db_user_username = db.query(User).filter(User.username == user.username).first()
    if db_user_username:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        username=user.username,
        allow_mentions=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User created successfully"}

@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/users/me", response_model=UserResponse)
async def update_user_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if username is being changed and if it's already taken
    if user_update.username and user_update.username != current_user.username:
        existing_user = db.query(User).filter(User.username == user_update.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already taken")
    
    # Build update dict
    update_data = {}
    if user_update.username is not None:
        update_data['username'] = user_update.username
    if user_update.full_name is not None:
        update_data['full_name'] = user_update.full_name
    if user_update.phone is not None:
        update_data['phone'] = user_update.phone
    if user_update.bio is not None:
        update_data['bio'] = user_update.bio
    if user_update.allow_mentions is not None:
        update_data['allow_mentions'] = user_update.allow_mentions
    
    update_data['updated_at'] = datetime.utcnow()
    
    # Update using SQLAlchemy update
    db.query(User).filter(User.id == current_user.id).update(update_data)
    db.commit()
    db.refresh(current_user)
    return current_user

@app.post("/users/me/avatar")
async def upload_avatar(
    avatar: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload or update user avatar"""
    # Save avatar file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{current_user.id}_{avatar.filename}"
    file_path = UPLOAD_DIR / "avatars" / filename
    avatar_url = save_upload_file(avatar, file_path)
    
    # Update user avatar_url
    db.query(User).filter(User.id == current_user.id).update({
        'avatar_url': avatar_url,
        'updated_at': datetime.utcnow()
    })
    db.commit()
    db.refresh(current_user)
    
    return {"avatar_url": avatar_url, "message": "Avatar uploaded successfully"}

@app.post("/users/me/change-password")
async def change_password(
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify current password
    if not verify_password(password_change.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password using SQLAlchemy update
    db.query(User).filter(User.id == current_user.id).update({
        'hashed_password': get_password_hash(password_change.new_password),
        'updated_at': datetime.utcnow()
    })
    db.commit()
    return {"message": "Password changed successfully"}

@app.delete("/users/me")
async def delete_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db.delete(current_user)
    db.commit()
    return {"message": "Account deleted successfully"}

# ========== BLOG POST ENDPOINTS ==========

@app.post("/posts", response_model=BlogPostResponse, status_code=status.HTTP_201_CREATED)
async def create_blog_post(
    title: str = Form(...),
    content: str = Form(...),
    media: UploadFile | None = File(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    media_url = None
    if media is not None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{current_user.id}_{media.filename}"
        file_path = UPLOAD_DIR / "posts" / filename
        media_url = save_upload_file(media, file_path)
    
    db_post = BlogPost(
        user_id=current_user.id,
        title=title,
        content=content,
        media_url=media_url
    )
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    
    # Create mention notifications
    create_mention_notifications(content, db_post.id, None, current_user.id, db)
    db.commit()
    
    # Get user data for response
    user = db.query(User).filter(User.id == current_user.id).first()
    avatar_url_str = str(user.avatar_url) if (user and hasattr(user, 'avatar_url') and user.avatar_url is not None) else None
    
    response = BlogPostResponse.model_validate(db_post)
    response.author_username = str(current_user.username)
    response.author_avatar_url = avatar_url_str
    return response

@app.get("/posts", response_model=list[BlogPostResponse])
async def get_all_posts(
    skip: int = 0,
    limit: int = 20,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(BlogPost, User).join(User, BlogPost.user_id == User.id)
    
    if search:
        query = query.filter(
            (BlogPost.title.contains(search)) | (BlogPost.content.contains(search))
        )
    
    posts = query.order_by(BlogPost.created_at.desc()).offset(skip).limit(limit).all()
    
    results = []
    for post, user in posts:
        post_response = BlogPostResponse.model_validate(post)
        post_response.author_username = user.username
        avatar_url_str = str(user.avatar_url) if (hasattr(user, 'avatar_url') and user.avatar_url is not None) else None
        post_response.author_avatar_url = avatar_url_str
        
        # Add counts (wrapped in try-catch for tables that might not exist yet)
        try:
            post_response.like_count = db.query(Like).filter(Like.post_id == post.id).count()
            post_response.comment_count = db.query(Comment).filter(Comment.post_id == post.id).count()
            post_response.repost_count = db.query(Repost).filter(Repost.post_id == post.id).count()
        except:
            post_response.like_count = 0
            post_response.comment_count = 0
            post_response.repost_count = 0
        
        results.append(post_response)
    
    return results

@app.get("/posts/{post_id}", response_model=BlogPostResponse)
async def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    user = db.query(User).filter(User.id == post.user_id).first()
    post_response = BlogPostResponse.model_validate(post)
    post_response.author_username = str(user.username) if user else None
    return post_response

@app.put("/posts/{post_id}", response_model=BlogPostResponse)
async def update_post(
    post_id: int,
    post_update: BlogPostUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Compare values properly
    if post.user_id.__eq__(current_user.id) is False:
        raise HTTPException(status_code=403, detail="Not authorized to edit this post")
    
    update_data = {}
    if post_update.title is not None:
        update_data['title'] = post_update.title
    if post_update.content is not None:
        update_data['content'] = post_update.content
    update_data['updated_at'] = datetime.utcnow()
    
    db.query(BlogPost).filter(BlogPost.id == post_id).update(update_data)
    db.commit()
    db.refresh(post)
    
    post_response = BlogPostResponse.model_validate(post)
    post_response.author_username = str(current_user.username)
    return post_response

@app.delete("/posts/{post_id}")
async def delete_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Compare values properly
    if post.user_id.__eq__(current_user.id) is False:
        raise HTTPException(status_code=403, detail="Not authorized to delete this post")
    
    db.delete(post)
    db.commit()
    return {"message": "Post deleted successfully"}

@app.get("/users/{user_id}/posts", response_model=list[BlogPostResponse])
async def get_user_posts(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    posts = db.query(BlogPost).filter(BlogPost.user_id == user_id).order_by(BlogPost.created_at.desc()).all()
    
    results = []
    for post in posts:
        post_response = BlogPostResponse.model_validate(post)
        post_response.author_username = str(user.username)
        results.append(post_response)
    
    return results

# ========== COMMENTS ENDPOINTS ==========

@app.post("/posts/{post_id}/comments", response_model=CommentResponse, status_code=status.HTTP_201_CREATED)
async def create_comment(
    post_id: int,
    comment: CommentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    db_comment = Comment(
        post_id=post_id,
        user_id=current_user.id,
        parent_comment_id=comment.parent_comment_id,
        content=comment.content
    )
    db.add(db_comment)
    db.commit()
    db.refresh(db_comment)
    
    # Create mention notifications
    create_mention_notifications(comment.content, post_id, db_comment.id, current_user.id, db)
    
    # Notify post author about comment (if not self-comment)
    if post.user_id != current_user.id:
        notif = Notification(
            user_id=post.user_id,
            type="comment",
            from_user_id=current_user.id,
            post_id=post_id,
            comment_id=db_comment.id,
            message=f"{current_user.username} commented on your post"
        )
        db.add(notif)
    
    # If it's a reply, notify parent comment author
    parent_user = None
    if comment.parent_comment_id:
        parent = db.query(Comment).filter(Comment.id == comment.parent_comment_id).first()
        if parent:
            parent_user = db.query(User).filter(User.id == parent.user_id).first()
        if parent and parent.user_id != current_user.id:
            notif = Notification(
                user_id=parent.user_id,
                type="comment",
                from_user_id=current_user.id,
                post_id=post_id,
                comment_id=db_comment.id,
                message=f"{current_user.username} replied to your comment"
            )
            db.add(notif)
    
    db.commit()
    
    comment_response = CommentResponse.model_validate(db_comment)
    comment_response.author_username = str(current_user.username)
    comment_response.author_avatar_url = str(current_user.avatar_url) if getattr(current_user, "avatar_url", None) else None
    comment_response.parent_username = parent_user.username if parent_user else None
    comment_response.reply_count = 0
    return comment_response

@app.get("/posts/{post_id}/comments", response_model=list[CommentResponse])
async def get_post_comments(post_id: int, db: Session = Depends(get_db)):
    rows = (
        db.query(Comment, User)
        .join(User, Comment.user_id == User.id)
        .filter(Comment.post_id == post_id)
        .order_by(Comment.created_at.asc())
        .all()
    )

    if not rows:
        return []

    users_by_comment: dict[int, User] = {}
    reply_counts: dict[int, int] = defaultdict(int)

    for comment, user in rows:
        users_by_comment[comment.id] = user
        if comment.parent_comment_id:
            reply_counts[comment.parent_comment_id] += 1

    results: list[CommentResponse] = []
    for comment, user in rows:
        comment_response = CommentResponse.model_validate(comment)
        comment_response.author_username = user.username
        comment_response.author_avatar_url = (
            str(user.avatar_url)
            if getattr(user, "avatar_url", None)
            else None
        )
        comment_response.reply_count = reply_counts.get(comment.id, 0)

        if comment.parent_comment_id:
            parent_user = users_by_comment.get(comment.parent_comment_id)
            comment_response.parent_username = parent_user.username if parent_user else None

        results.append(comment_response)

    return results

@app.delete("/comments/{comment_id}")
async def delete_comment(
    comment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    # Compare values properly
    if comment.user_id.__eq__(current_user.id) is False:
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")
    
    db.delete(comment)
    db.commit()
    return {"message": "Comment deleted successfully"}

# ========== MESSAGING ENDPOINTS ==========

@app.post("/messages", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    receiver_id: int = Form(...),
    message: Optional[str] = Form(None),
    media: Optional[List[UploadFile]] = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    receiver = db.query(User).filter(User.id == receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    # Validate at least message or media exists
    if not message and (not media or len(media) == 0):
        raise HTTPException(status_code=400, detail="Message must contain text or media")
    
    media_url = None
    if media and len(media) > 0:
        # Save the first media file
        file = media[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{current_user.id}_{file.filename}"
        file_path = UPLOAD_DIR / "messages" / filename
        media_url = save_upload_file(file, file_path)
    
    db_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        message=message if message else None,
        media_url=media_url
    )
    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    
    message_response = MessageResponse.model_validate(db_message)
    message_response.sender_username = str(current_user.username)
    message_response.receiver_username = str(receiver.username)
    message_response.read_status = bool(db_message.read_status)
    return message_response

@app.get("/messages/conversations")
async def get_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Get list of users the current user has messaged with
    conversations = db.execute(text("""
        SELECT 
            other_user_id,
            username,
            avatar_url,
            last_message_time,
            last_message
        FROM (
            SELECT DISTINCT 
                CASE 
                    WHEN sender_id = :user_id THEN receiver_id 
                    ELSE sender_id 
                END as other_user_id,
                u.username,
                u.avatar_url,
                m.timestamp as last_message_time,
                m.message as last_message,
                ROW_NUMBER() OVER (PARTITION BY CASE 
                    WHEN sender_id = :user_id THEN receiver_id 
                    ELSE sender_id 
                END ORDER BY m.timestamp DESC) as rn
            FROM messages m
            JOIN users u ON u.id = CASE 
                WHEN m.sender_id = :user_id THEN m.receiver_id 
                ELSE m.sender_id 
            END
            WHERE sender_id = :user_id OR receiver_id = :user_id
        ) ranked
        WHERE rn = 1
        ORDER BY last_message_time DESC
    """), {"user_id": current_user.id}).fetchall()
    
    return [{
        "other_user_id": c[0], 
        "username": c[1], 
        "avatar_url": c[2], 
        "last_message_time": c[3],
        "last_message": c[4]
    } for c in conversations]

@app.get("/messages/{other_user_id}", response_model=list[MessageResponse])
async def get_messages_with_user(
    other_user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    messages = db.query(Message, User.username.label('sender_username'), User.username.label('receiver_username')).join(
        User, Message.sender_id == User.id
    ).filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark messages as read
    db.query(Message).filter(
        Message.sender_id == other_user_id,
        Message.receiver_id == current_user.id,
        Message.read_status == 0
    ).update({Message.read_status: 1})
    db.commit()
    
    results = []
    for message, sender_name, _ in messages:
        message_response = MessageResponse.model_validate(message)
        message_response.sender_username = sender_name
        message_response.read_status = bool(message.read_status)
        results.append(message_response)
    
    return results

@app.delete("/messages/conversation/{other_user_id}")
async def delete_conversation(
    other_user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete all messages in a conversation between current user and another user"""
    deleted_count = db.query(Message).filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.id))
    ).delete()
    db.commit()
    
    return {
        "message": "Conversation cleared successfully",
        "deleted_count": deleted_count
    }

@app.get("/users/search")
async def search_users(q: str, db: Session = Depends(get_db)):
    users = db.query(User).filter(User.username.contains(q)).limit(10).all()
    return [{"id": u.id, "username": u.username, "full_name": u.full_name, "avatar_url": getattr(u, 'avatar_url', None)} for u in users]

@app.get("/users/mentionable")
async def list_mentionable_users(
    q: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Return users who allow mentions, optionally filtered by query."""
    query = db.query(User).filter(User.allow_mentions == True, User.id != current_user.id)
    if q:
        query = query.filter(User.username.ilike(f"%{q}%"))
    users = query.order_by(User.username.asc()).limit(15).all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "avatar_url": getattr(user, "avatar_url", None)
        }
        for user in users
    ]

# Message Edit/Delete endpoints
@app.put("/messages/{message_id}")
async def update_message(
    message_id: int,
    message_update: MessageUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update a message (only sender can edit)"""
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to edit this message")
    
    msg.message = message_update.message
    db.commit()
    db.refresh(msg)
    return msg

@app.delete("/messages/{message_id}")
async def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a message (only sender can delete)"""
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this message")
    
    db.delete(msg)
    db.commit()
    return {"message": "Message deleted successfully"}

# Report endpoints
@app.post("/reports", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def create_report(
    report: ReportCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new report"""
    new_report = Report(
        reporter_id=current_user.id,
        report_type=report.report_type,
        target_id=report.target_id,
        reason=report.reason,
        details=report.details,
        status="pending"
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report

@app.get("/reports", response_model=List[ReportResponse])
async def get_reports(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all reports (for admin/moderators)"""
    reports = db.query(Report).all()
    return reports

# Block endpoints
@app.post("/users/block/{user_id}")
async def block_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Block a user"""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot block yourself")
    
    # Check if already blocked
    existing = db.query(BlockedUser).filter(
        BlockedUser.blocker_id == current_user.id,
        BlockedUser.blocked_id == user_id
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="User already blocked")
    
    block = BlockedUser(blocker_id=current_user.id, blocked_id=user_id)
    db.add(block)
    db.commit()
    return {"message": "User blocked successfully"}

@app.delete("/users/block/{user_id}")
async def unblock_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Unblock a user"""
    block = db.query(BlockedUser).filter(
        BlockedUser.blocker_id == current_user.id,
        BlockedUser.blocked_id == user_id
    ).first()
    
    if not block:
        raise HTTPException(status_code=404, detail="Block not found")
    
    db.delete(block)
    db.commit()
    return {"message": "User unblocked successfully"}

@app.get("/users/blocked")
async def get_blocked_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of blocked users"""
    blocks = db.query(BlockedUser).filter(BlockedUser.blocker_id == current_user.id).all()
    blocked_ids = [b.blocked_id for b in blocks]
    users = db.query(User).filter(User.id.in_(blocked_ids)).all()
    return [{"id": u.id, "username": u.username, "avatar_url": u.avatar_url} for u in users]

# Like/Unlike endpoints
@app.post("/posts/{post_id}/like")
async def like_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Like a post"""
    existing = db.query(Like).filter(Like.user_id == current_user.id, Like.post_id == post_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already liked")
    
    like = Like(user_id=current_user.id, post_id=post_id)
    db.add(like)
    
    # Create notification
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if post and post.user_id != current_user.id:
        notif = Notification(
            user_id=post.user_id,
            type="like",
            from_user_id=current_user.id,
            post_id=post_id,
            message=f"{current_user.username} liked your post"
        )
        db.add(notif)
    
    db.commit()
    return {"message": "Post liked"}

@app.delete("/posts/{post_id}/like")
async def unlike_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Unlike a post"""
    like = db.query(Like).filter(Like.user_id == current_user.id, Like.post_id == post_id).first()
    if not like:
        raise HTTPException(status_code=404, detail="Like not found")
    
    db.delete(like)
    db.commit()
    return {"message": "Post unliked"}

# Repost/Quote endpoints
@app.post("/posts/{post_id}/repost")
async def repost_post(
    post_id: int,
    repost_data: RepostCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Repost or quote tweet a post"""
    existing = db.query(Repost).filter(Repost.user_id == current_user.id, Repost.post_id == post_id).first()
    if existing and not repost_data.quote_text:
        raise HTTPException(status_code=400, detail="Already reposted")
    
    repost = Repost(user_id=current_user.id, post_id=post_id, quote_text=repost_data.quote_text)
    db.add(repost)
    
    # Create notification
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if post and post.user_id != current_user.id:
        notif = Notification(
            user_id=post.user_id,
            type="repost",
            from_user_id=current_user.id,
            post_id=post_id,
            message=f"{current_user.username} reposted your post"
        )
        db.add(notif)
    
    db.commit()
    return {"message": "Post reposted"}

@app.delete("/posts/{post_id}/repost")
async def unrepost_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove repost"""
    repost = db.query(Repost).filter(Repost.user_id == current_user.id, Repost.post_id == post_id).first()
    if not repost:
        raise HTTPException(status_code=404, detail="Repost not found")
    
    db.delete(repost)
    db.commit()
    return {"message": "Repost removed"}

# Bookmark endpoints
@app.post("/posts/{post_id}/bookmark")
async def bookmark_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Bookmark a post"""
    existing = db.query(Bookmark).filter(Bookmark.user_id == current_user.id, Bookmark.post_id == post_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already bookmarked")
    
    bookmark = Bookmark(user_id=current_user.id, post_id=post_id)
    db.add(bookmark)
    db.commit()
    return {"message": "Post bookmarked"}

@app.delete("/posts/{post_id}/bookmark")
async def unbookmark_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove bookmark"""
    bookmark = db.query(Bookmark).filter(Bookmark.user_id == current_user.id, Bookmark.post_id == post_id).first()
    if not bookmark:
        raise HTTPException(status_code=404, detail="Bookmark not found")
    
    db.delete(bookmark)
    db.commit()
    return {"message": "Bookmark removed"}

@app.get("/bookmarks")
async def get_bookmarks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's bookmarked posts"""
    bookmarks = db.query(Bookmark).filter(Bookmark.user_id == current_user.id).all()
    post_ids = [b.post_id for b in bookmarks]
    posts = db.query(BlogPost, User).join(User, BlogPost.user_id == User.id).filter(BlogPost.id.in_(post_ids)).all()
    
    results = []
    for post, user in posts:
        post_response = BlogPostResponse.model_validate(post)
        post_response.author_username = user.username
        post_response.author_avatar_url = str(user.avatar_url) if hasattr(user, 'avatar_url') and user.avatar_url else None
        results.append(post_response)
    
    return results

# Follow/Unfollow endpoints
@app.post("/users/{user_id}/follow")
async def follow_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Follow a user"""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot follow yourself")
    
    existing = db.query(Follow).filter(Follow.follower_id == current_user.id, Follow.following_id == user_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already following")
    
    follow = Follow(follower_id=current_user.id, following_id=user_id)
    db.add(follow)
    
    # Create notification
    notif = Notification(
        user_id=user_id,
        type="follow",
        from_user_id=current_user.id,
        message=f"{current_user.username} followed you"
    )
    db.add(notif)
    
    db.commit()
    return {"message": "User followed"}

@app.delete("/users/{user_id}/follow")
async def unfollow_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Unfollow a user"""
    follow = db.query(Follow).filter(Follow.follower_id == current_user.id, Follow.following_id == user_id).first()
    if not follow:
        raise HTTPException(status_code=404, detail="Not following")
    
    db.delete(follow)
    db.commit()
    return {"message": "User unfollowed"}

@app.get("/users/{user_id}/followers")
async def get_followers(user_id: int, db: Session = Depends(get_db)):
    """Get user's followers"""
    follows = db.query(Follow).filter(Follow.following_id == user_id).all()
    follower_ids = [f.follower_id for f in follows]
    users = db.query(User).filter(User.id.in_(follower_ids)).all()
    return [{"id": u.id, "username": u.username, "avatar_url": u.avatar_url, "full_name": u.full_name} for u in users]

@app.get("/users/{user_id}/following")
async def get_following(user_id: int, db: Session = Depends(get_db)):
    """Get users that this user follows"""
    follows = db.query(Follow).filter(Follow.follower_id == user_id).all()
    following_ids = [f.following_id for f in follows]
    users = db.query(User).filter(User.id.in_(following_ids)).all()
    return [{"id": u.id, "username": u.username, "avatar_url": u.avatar_url, "full_name": u.full_name} for u in users]

# Notification endpoints
@app.get("/notifications", response_model=List[NotificationResponse])
async def get_notifications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's notifications"""
    notifs = db.query(Notification).filter(Notification.user_id == current_user.id).order_by(Notification.created_at.desc()).limit(50).all()
    
    results = []
    for notif in notifs:
        from_user = db.query(User).filter(User.id == notif.from_user_id).first()
        notif_response = NotificationResponse.model_validate(notif)
        notif_response.from_username = from_user.username if from_user else "Unknown"
        notif_response.from_avatar_url = str(from_user.avatar_url) if from_user and hasattr(from_user, 'avatar_url') and from_user.avatar_url else None
        results.append(notif_response)
    
    return results

@app.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark notification as read"""
    notif = db.query(Notification).filter(Notification.id == notification_id, Notification.user_id == current_user.id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notif.read_status = 1
    db.commit()
    return {"message": "Notification marked as read"}

@app.put("/notifications/read-all")
async def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark all notifications as read"""
    db.query(Notification).filter(Notification.user_id == current_user.id).update({"read_status": 1})
    db.commit()
    return {"message": "All notifications marked as read"}

# Mention detection and notification
def extract_mentions(text: str):
    """Extract @username mentions from text"""
    return re.findall(r'@(\w+)', text)

def create_mention_notifications(text: str, post_id: Optional[int], comment_id: Optional[int], current_user_id: int, db: Session):
    """Create notifications for mentioned users"""
    usernames = extract_mentions(text)
    for username in usernames:
        user = db.query(User).filter(User.username == username).first()
        if user and user.id != current_user_id and getattr(user, "allow_mentions", True):
            mention = Mention(
                post_id=post_id if post_id else None,
                comment_id=comment_id if comment_id else None,
                mentioned_user_id=user.id
            )
            db.add(mention)
            
            notif = Notification(
                user_id=user.id,
                type="mention",
                from_user_id=current_user_id,
                post_id=post_id,
                comment_id=comment_id,
                message=f"You were mentioned"
            )
            db.add(notif)

# Trending/Explore endpoint
@app.get("/trending")
async def get_trending(db: Session = Depends(get_db)):
    """Get trending posts based on likes and comments"""
    from sqlalchemy import func
    
    # Get posts with most engagement in last 24 hours
    recent_posts = db.query(BlogPost).filter(
        BlogPost.created_at >= datetime.utcnow() - timedelta(days=1)
    ).all()
    
    trending = []
    for post in recent_posts:
        like_count = db.query(Like).filter(Like.post_id == post.id).count()
        comment_count = db.query(Comment).filter(Comment.post_id == post.id).count()
        repost_count = db.query(Repost).filter(Repost.post_id == post.id).count()
        
        score = (like_count * 1) + (comment_count * 2) + (repost_count * 3)
        
        user = db.query(User).filter(User.id == post.user_id).first()
        post_response = BlogPostResponse.model_validate(post)
        post_response.author_username = user.username if user else None
        post_response.author_avatar_url = str(user.avatar_url) if user and hasattr(user, 'avatar_url') and user.avatar_url else None
        post_response.like_count = like_count
        post_response.comment_count = comment_count
        post_response.repost_count = repost_count
        
        trending.append({"post": post_response, "score": score})
    
    # Sort by score
    trending.sort(key=lambda x: x["score"], reverse=True)
    return [t["post"] for t in trending[:20]]

if __name__ == "__main__":
    import uvicorn
    Base.metadata.create_all(bind=engine)
    uvicorn.run(app, host="127.0.0.1", port=8000)
