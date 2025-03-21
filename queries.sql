CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE urls (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    short_key VARCHAR(50) UNIQUE NOT NULL,
    original_url TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);