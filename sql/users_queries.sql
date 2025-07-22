INSERT INTO users (name, email, password)
VALUES ('Marcelo Silva', 'marcelo@example.com', 'senha123');

SELECT * FROM users;

SELECT * FROM users WHERE email = 'marcelo@example.com';

SELECT * FROM users WHERE verified = true;

UPDATE users
SET verified = true, updated_at = NOW()
WHERE email = 'marcelo@example.com';

DELETE FROM users WHERE email = 'marcelo@example.com';

SELECT *
FROM users
WHERE name ILIKE '%mar%'
ORDER BY similarity(name, 'mar') DESC;

SELECT * FROM users WHERE role = 'admin';

UPDATE users
SET role = 'admin'
WHERE email = 'marcelo@example.com';

SELECT *
FROM users
WHERE created_at >= NOW() - INTERVAL '7 days';

