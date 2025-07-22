INSERT INTO post_comments (id, news_post_id, content, author_id, author_name)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM news_posts WHERE url = 'https://example.com/post-1'),
    'Ótimo post!',
    (SELECT id FROM users WHERE email = 'marcelo@example.com'),
    'Marcelo Silva'
);

SELECT c.*
FROM post_comments c
JOIN news_posts p ON p.id = c.news_post_id
WHERE p.url = 'https://example.com/post-1';

SELECT news_post_id, COUNT(*) AS total_comentarios
FROM post_comments
GROUP BY news_post_id;

SELECT *
FROM post_comments
WHERE author_id = (SELECT id FROM users WHERE email = 'marcelo@example.com');

