CREATE TABLE IF NOT EXISTS `lyrae_keys` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `public_id` VARCHAR(32) NOT NULL,
    `secret_hash` VARCHAR(255) NOT NULL,
    `last_used_at` DATETIME DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_lyrae_user` (`user_id`),
    UNIQUE KEY `uk_lyrae_public_id` (`public_id`),
    CONSTRAINT `fk_lyrae_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
