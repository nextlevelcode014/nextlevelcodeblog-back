use crate::{
    domains::posts::{
        model::{NewsPost, NewsPostWithComments},
        query::CreateNewsPostDto,
        repository::NewsPostsRepository,
    },
    infrastructure::db::PostgresRepo,
    Error, Result,
};
use tracing::{info, instrument, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct NewsPostsService {
    repo: PostgresRepo,
}

impl NewsPostsService {
    pub fn new(repo: PostgresRepo) -> Self {
        Self { repo }
    }

    #[instrument(name = "get_news_posts", skip(self))]
    pub async fn get_news_posts(&self) -> Result<Vec<NewsPost>> {
        let newspost = self.repo.get_news_posts().await?;
        info!(count = newspost.len(), "Retrieved news posts");
        Ok(newspost)
    }

    #[instrument(name = "create_news_post", skip(self, news_post, author_id))]
    pub async fn create_news_post(
        &self,
        news_post: CreateNewsPostDto,
        author_id: Uuid,
    ) -> Result<()> {
        info!(%author_id, title = %news_post.title, "Creating news post");

        self.repo
            .create_news_post(
                &news_post.title,
                &news_post.url,
                &news_post.description,
                author_id,
            )
            .await?;
        info!(%author_id, "News post created successfully");
        Ok(())
    }

    #[instrument(
        name = "update_news_post",
        skip(
            self,
            update_news_post_url,
            update_news_post_title,
            update_news_post_description
        )
    )]
    pub async fn update_news_post(
        &self,
        author_id: Uuid,
        news_post_id: &str,
        update_news_post_url: Option<&str>,
        update_news_post_title: Option<&str>,
        update_news_post_description: Option<&str>,
    ) -> Result<()> {
        let news_post_id = Uuid::parse_str(news_post_id).map_err(|_| {
            warn!(news_post_id = %news_post_id, "Invalid news post ID format");
            Error::BadRequest {
                message: "Invalid ID format".into(),
            }
        })?;

        self.is_news_post_owner(news_post_id, author_id).await?;

        info!(%news_post_id, "Updating news post");
        self.repo
            .update_news_post(
                news_post_id,
                update_news_post_title,
                update_news_post_url,
                update_news_post_description,
            )
            .await?;
        info!(%news_post_id, "News post updated successfully");
        Ok(())
    }

    #[instrument(name = "delete_news_post", skip(self))]
    pub async fn delete_news_post(&self, news_post_id: &str, author_id: Uuid) -> Result<()> {
        info!(%news_post_id, "Deleting news post");
        let news_post_id = Uuid::parse_str(news_post_id).map_err(|_| {
            warn!(%news_post_id, "Invalid news post ID format");
            Error::BadRequest {
                message: "Invalid ID format".into(),
            }
        })?;
        self.is_news_post_owner(news_post_id, author_id).await?;
        self.repo.delete_news_post(news_post_id).await?;
        info!(%news_post_id, "News post deleted successfully");
        Ok(())
    }

    #[instrument(name = "get_all_posts_with_comments", skip(self))]
    pub async fn get_all_posts_with_comments(&self) -> Result<Vec<NewsPostWithComments>> {
        let posts_with_comments = self.repo.get_all_posts_with_comments().await?;
        info!(
            count = posts_with_comments.len(),
            "Retrieved all posts with comments"
        );
        Ok(posts_with_comments)
    }

    #[instrument(name = "create_comment", skip(self, post_id, content, author_id))]
    pub async fn create_comment(
        &self,
        post_id: &str,
        content: &str,
        author_id: Uuid,
    ) -> Result<()> {
        info!(%post_id, %author_id, "Creating comment");
        let post_id = Uuid::parse_str(post_id).map_err(|_| {
            warn!(%post_id, "Invalid post ID format");
            Error::BadRequest {
                message: "Invalid ID format".to_string(),
            }
        })?;

        self.repo
            .create_comment(post_id, content, author_id)
            .await?;
        info!(%post_id, "Comment created successfully");
        Ok(())
    }

    #[instrument(name = "update_comment", skip(self, content))]
    pub async fn update_comment(
        &self,
        comment_id: &str,
        content: Option<&str>,
        author_id: Uuid,
    ) -> Result<()> {
        info!(%comment_id, "Updating comment");
        let comment_id = Uuid::parse_str(comment_id).map_err(|_| {
            warn!(%comment_id, "Invalid comment ID format");
            Error::BadRequest {
                message: "Invalid ID format".into(),
            }
        })?;
        self.is_news_post_comment_owner(comment_id, author_id)
            .await?;
        self.repo.update_comment(comment_id, content).await?;
        info!(%comment_id, "Comment updated successfully");
        Ok(())
    }

    #[instrument(name = "delete_comment", skip(self))]
    pub async fn delete_comment(&self, comment_id: &str, author_id: Uuid) -> Result<()> {
        info!(%comment_id, "Deleting comment");
        let comment_id = Uuid::parse_str(comment_id).map_err(|_| {
            warn!(%comment_id, "Invalid comment ID format");
            Error::BadRequest {
                message: "Invalid ID format".into(),
            }
        })?;
        self.is_news_post_comment_owner(comment_id, author_id)
            .await?;
        self.repo.delete_comment(comment_id).await?;
        info!(%comment_id, "Comment deleted successfully");
        Ok(())
    }

    #[instrument(name = "is_news_post_owner", skip(self))]
    async fn is_news_post_owner(&self, news_post_id: Uuid, author_id: Uuid) -> Result<()> {
        let owner = self.repo.get_author_id_from_news_post(news_post_id).await?;

        if owner.author_id != author_id {
            warn!(%author_id, "Post doest not beleong to the user");
            return Err(Error::Unauthorized);
        }

        Ok(())
    }

    #[instrument(name = "is_news_post_comment_owner", skip(self))]
    async fn is_news_post_comment_owner(&self, comment_id: Uuid, author_id: Uuid) -> Result<()> {
        let owner = self.repo.get_author_id_from_comment(comment_id).await?;

        if owner.author_id != author_id {
            warn!(%author_id, "Post comment doest not beleong to the user");
            return Err(Error::Unauthorized);
        }

        Ok(())
    }
}
