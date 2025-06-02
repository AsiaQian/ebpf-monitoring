CREATE TABLE products (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    item_name VARCHAR(255) NOT NULL UNIQUE, -- item_name 应该是唯一的
    stock INT NOT NULL DEFAULT 0
);