use crate::{
    domains::posts::model::{
        AuthorCommentId, AuthorId, NewsPost, PostComment, PostCommentWithComment,
    },
    infrastructure::db::PostgresRepo,
    Result,
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait NewsPostsRepository: Sync + Send {
    async fn get_author_id_from_news_post(&self, news_post_id: Uuid) -> Result<AuthorId>;
    async fn get_author_id_from_comment(&self, comment_id: Uuid) -> Result<AuthorCommentId>;
    async fn get_news_posts(&self) -> Result<Vec<NewsPost>>;
    async fn create_news_post(
        &self,
        title: &str,
        url: &str,
        description: &str,
        author_id: Uuid,
    ) -> Result<()>;
    async fn update_news_post(
        &self,
        post_id: Uuid,
        title: Option<&str>,
        url: Option<&str>,
        description: Option<&str>,
    ) -> Result<()>;
    async fn delete_news_post(&self, post_id: Uuid) -> Result<()>;
    async fn create_comment(
        &self,
        post_id: Uuid,
        content: &str,
        author_id: Uuid,
    ) -> Result<PostComment>;
    async fn update_comment(&self, comment_id: Uuid, content: Option<&str>) -> Result<()>;
    async fn delete_comment(&self, comment_id: Uuid) -> Result<()>;
    async fn get_posts_with_comments(&self) -> Result<Vec<PostCommentWithComment>>;
    async fn get_all_posts_with_comments(&self) -> Result<Vec<PostCommentWithComment>>;
    async fn get_post_with_comments_by_id(
        &self,
        post_id: Uuid,
    ) -> Result<Vec<PostCommentWithComment>>;
}

#[async_trait]
impl NewsPostsRepository for PostgresRepo {
    async fn get_author_id_from_news_post(&self, news_post_id: Uuid) -> Result<AuthorId> {
        let post = sqlx::query_as::<_, AuthorId>(
            r#"
            SELECT author_id
            FROM news_posts
            WHERE id = $1
            "#,
        )
        .bind(news_post_id)
        .fetch_one(self.pool())
        .await?;

        Ok(post)
    }

    async fn get_author_id_from_comment(&self, comment_id: Uuid) -> Result<AuthorCommentId> {
        let post = sqlx::query_as::<_, AuthorCommentId>(
            r#"
            SELECT author_id
            FROM post_comments
            WHERE id = $1
            "#,
        )
        .bind(comment_id)
        .fetch_one(self.pool())
        .await?;

        Ok(post)
    }

    async fn get_news_posts(&self) -> Result<Vec<NewsPost>> {
        let posts = sqlx::query_as::<_, NewsPost>(
            r#"
            SELECT id, title, author_id, url, description, created_at FROM news_posts
            "#,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(posts)
    }

    async fn create_news_post(
        &self,
        title: &str,
        url: &str,
        description: &str,
        author_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO news_posts (title, url, description, author_id)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(title)
        .bind(url)
        .bind(description)
        .bind(author_id)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn update_news_post(
        &self,
        post_id: Uuid,
        title: Option<&str>,
        url: Option<&str>,
        description: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE news_posts
            SET url = COALESCE($2, url),
                description = COALESCE($3, description),
                title = COALESCE($4, title)
            WHERE id = $1
            "#,
        )
        .bind(post_id)
        .bind(url)
        .bind(description)
        .bind(title)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn create_comment(
        &self,
        post_id: Uuid,
        content: &str,
        author_id: Uuid,
    ) -> Result<PostComment> {
        let id = Uuid::now_v7();

        let comment = sqlx::query_as::<_, PostComment>(
            r#"
            INSERT INTO post_comments (id, news_post_id, content, author_id)
            VALUES ($1, $2, $3, $4)
            RETURNING id, content, author_id
            "#,
        )
        .bind(id)
        .bind(post_id)
        .bind(content)
        .bind(author_id)
        .fetch_one(self.pool())
        .await?;

        Ok(comment)
    }

    async fn update_comment(&self, comment_id: Uuid, content: Option<&str>) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE post_comments
            SET content = COALESCE($2, content)
            WHERE id = $1
            "#,
        )
        .bind(comment_id)
        .bind(content)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn delete_comment(&self, comment_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM post_comments WHERE id = $1
            "#,
        )
        .bind(comment_id)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn delete_news_post(&self, post_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM news_posts WHERE id = $1
            "#,
        )
        .bind(post_id)
        .execute(self.pool())
        .await?;

        Ok(())
    }

    async fn get_posts_with_comments(&self) -> Result<Vec<PostCommentWithComment>> {
        let result = sqlx::query_as::<_, PostCommentWithComment>(
            "
        SELECT 
            np.id AS post_id,
            np.title,
            np.url,
            np.description,
            np.created_at AS post_created_at,
            u.name AS author_name,
            pc.id AS comment_id,
            pc.content AS comment_content,
            pc.created_at AS comment_created_at,
            cu.name AS commenter_name
        FROM news_posts np
        JOIN users u ON np.author_id = u.id
        JOIN post_comments pc ON pc.news_post_id = np.id
        JOIN users cu ON pc.author_id = cu.id
        ORDER BY np.created_at DESC, pc.created_at ASC
        ",
        )
        .fetch_all(self.pool())
        .await?;

        Ok(result)
    }

    async fn get_all_posts_with_comments(&self) -> Result<Vec<PostCommentWithComment>> {
        let result = sqlx::query_as::<_, PostCommentWithComment>(
            "
        SELECT 
            np.id AS post_id,
            np.title,
            np.url,
            np.description,
            np.created_at AS post_created_at,
            u.name AS author_name,
            pc.id AS comment_id,
            pc.content AS comment_content,
            pc.created_at AS comment_created_at,
            cu.name AS commenter_name
        FROM news_posts np
        JOIN users u ON np.author_id = u.id
        LEFT JOIN post_comments pc ON pc.news_post_id = np.id
        LEFT JOIN users cu ON pc.author_id = cu.id
        ORDER BY np.created_at DESC, pc.created_at ASC
        ",
        )
        .fetch_all(self.pool())
        .await?;

        Ok(result)
    }

    async fn get_post_with_comments_by_id(
        &self,
        post_id: Uuid,
    ) -> Result<Vec<PostCommentWithComment>> {
        let result = sqlx::query_as::<_, PostCommentWithComment>(
            "
        SELECT 
            np.id AS post_id,
            np.title,
            np.url,
            np.description,
            np.created_at AS post_created_at,
            u.name AS author_name,
            pc.id AS comment_id,
            pc.content AS comment_content,
            pc.created_at AS comment_created_at,
            cu.name AS commenter_name
        FROM news_posts np
        JOIN users u ON np.author_id = u.id
        LEFT JOIN post_comments pc ON pc.news_post_id = np.id
        LEFT JOIN users cu ON pc.author_id = cu.id
        WHERE np.id = $1
        ORDER BY pc.created_at ASC
        ",
        )
        .bind(post_id)
        .fetch_all(self.pool())
        .await?;

        Ok(result)
    }
}
