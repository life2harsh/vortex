-- Migration: Add media support columns
-- Date: 2025-10-30
-- Description: Adds avatar_url, media_url columns for media upload support

-- Add avatar_url column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500);

-- Add media_url column to blog_posts table
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS media_url VARCHAR(500);

-- Modify messages table to make message optional and add media_url
ALTER TABLE messages ALTER COLUMN message DROP NOT NULL;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS media_url VARCHAR(500);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_avatar ON users(avatar_url);
CREATE INDEX IF NOT EXISTS idx_posts_media ON blog_posts(media_url);
CREATE INDEX IF NOT EXISTS idx_messages_media ON messages(media_url);
