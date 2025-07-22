-- Enables text search capabilities
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Generic trigger function to automatically update the 'updated_at' column on any row change
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Custom ENUM type for user roles
CREATE TYPE user_role AS ENUM ('user', 'admin');

CREATE TYPE auth_provider AS ENUM ('credentials', 'google');
--
-- Table: users
-- Stores user account information.
--
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    auth_provider auth_provider NOT NULL DEFAULT 'credentials',
    name VARCHAR(100) NOT NULL CHECK (TRIM(name) <> ''),
    email VARCHAR(255) NOT NULL UNIQUE CHECK (TRIM(email) <> ''),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash VARCHAR(255),
    google_sub TEXT UNIQUE,
    picture TEXT,
    role user_role NOT NULL DEFAULT 'user',
    verification_token VARCHAR(255),
    token_expires_at TIMESTAMP
    WITH
        TIME ZONE,
        created_at TIMESTAMP
    WITH
        TIME ZONE DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP
    WITH
        TIME ZONE DEFAULT NOW() NOT NULL,
        CHECK (
            (
                auth_provider = 'credentials'
                AND password_hash IS NOT NULL
                AND google_sub IS NULL
            )
            OR (
                auth_provider = 'google'
                AND google_sub IS NOT NULL
                AND password_hash IS NULL
            )
        )
);

-- Triggers

CREATE TRIGGER set_users_timestamp
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

--
-- Table: news_posts
-- Stores news articles or posts created by users.
--
CREATE TABLE news_posts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    title VARCHAR(255) NOT NULL CHECK (TRIM(title) <> ''),
    url TEXT NOT NULL CHECK (TRIM(url) <> ''),
    description TEXT NOT NULL CHECK (TRIM(description) <> ''),
    author_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMP
    WITH
        TIME ZONE DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP
    WITH
        TIME ZONE DEFAULT NOW() NOT NULL
);

-- Apply the updated_at trigger to the news_posts table
CREATE TRIGGER set_news_posts_timestamp
BEFORE UPDATE ON news_posts
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

--
-- Table: categories
-- Stores general-purpose categories that can be assigned to different content types.
--
CREATE TABLE categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name VARCHAR(100) UNIQUE NOT NULL
);

--
-- Table: post_categories (Junction Table)
-- Creates a many-to-many relationship between news_posts and categories.
--
CREATE TABLE post_categories (
    post_id UUID NOT NULL REFERENCES news_posts (id) ON DELETE CASCADE,
    category_id UUID NOT NULL REFERENCES categories (id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, category_id) -- Composite Primary Key
);

--
-- Table: post_comments
-- Stores comments made by users on news posts.
--
CREATE TABLE IF NOT EXISTS post_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    news_post_id UUID NOT NULL REFERENCES news_posts (id) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (TRIM(content) <> ''),
    author_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMP
    WITH
        TIME ZONE DEFAULT NOW() NOT NULL
);

--
-- Indexes for Performance
--
CREATE INDEX users_email_idx ON users (email);

CREATE INDEX users_verification_token_idx ON users (verification_token);

CREATE INDEX users_name_trgm_idx ON users USING GIN (name gin_trgm_ops);

CREATE INDEX post_comments_news_post_id_idx ON post_comments (news_post_id);

CREATE INDEX post_comments_author_id_idx ON post_comments (author_id);

CREATE INDEX post_categories_post_id_idx ON post_categories (post_id);

CREATE INDEX post_categories_category_id_idx ON post_categories (category_id);
