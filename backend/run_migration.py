"""
Database Migration Script - Add Media Support
Run this to add avatar_url and media_url columns to your database
"""

import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set.")

engine = create_engine(DATABASE_URL)

migrations = [
    # Add avatar_url to users table
    "ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500)",
    
    # Add media_url to blog_posts table
    "ALTER TABLE blog_posts ADD COLUMN media_url VARCHAR(500)",
    
    # Modify messages table to make message optional
    "ALTER TABLE messages MODIFY COLUMN message VARCHAR(1000) NULL",
    
    # Add media_url to messages table
    "ALTER TABLE messages ADD COLUMN media_url VARCHAR(500)",
]

print("🔄 Running database migrations...")
print("-" * 50)

try:
    with engine.connect() as conn:
        for i, migration in enumerate(migrations, 1):
            try:
                print(f"[{i}/{len(migrations)}] Executing: {migration[:60]}...")
                conn.execute(text(migration))
                conn.commit()
                print(f"    ✅ Success")
            except Exception as e:
                error_msg = str(e)
                # Check if it's just a "column already exists" error (which is OK)
                if "Duplicate column" in error_msg or "already exists" in error_msg:
                    print(f"    ⚠️  Column already exists (skipping)")
                else:
                    print(f"    ❌ Error: {error_msg}")
                    raise
    
    print("-" * 50)
    print("✅ All migrations completed successfully!")
    print("\nYou can now restart your backend server.")
    
except Exception as e:
    print("-" * 50)
    print(f"❌ Migration failed: {e}")
    print("\nPlease fix the error and try again.")
    exit(1)
