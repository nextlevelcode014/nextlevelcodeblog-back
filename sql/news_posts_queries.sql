INSERT INTO
    news_posts (
        id,
        title,
        url,
        description,
        author_id,
        author_name
    )
VALUES (
        gen_random_uuid (),
        'Post sobre PostgreSQL',
        'https://example.com/post-1',
        'Post sobre PostgreSQL',
        (
            SELECT id
            FROM users
            WHERE
                email = 'marcelo@example.com'
        ),
        'Marcelo Silva'
    );

SELECT p.*, u.name AS author_real_name
FROM news_posts p
    JOIN users u ON u.id = p.author_id;

SELECT author_id, COUNT(*) AS total_posts
FROM news_posts
GROUP BY
    author_id;