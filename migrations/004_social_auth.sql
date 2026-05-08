CREATE TABLE IF NOT EXISTS `user_identities` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `provider` ENUM('google', 'telegram') NOT NULL,
    `provider_user_id` VARCHAR(191) NOT NULL,
    `email` VARCHAR(255) DEFAULT NULL,
    `display_name` VARCHAR(255) DEFAULT NULL,
    `avatar_url` VARCHAR(1024) DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_provider_user` (`provider`, `provider_user_id`),
    UNIQUE KEY `uk_provider_user_id` (`user_id`, `provider`),
    INDEX `idx_identity_email` (`email`),
    CONSTRAINT `fk_user_identities_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `oauth_states` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `provider` ENUM('telegram') NOT NULL,
    `state` VARCHAR(191) NOT NULL,
    `code_verifier` VARCHAR(255) NOT NULL,
    `nonce` VARCHAR(255) DEFAULT NULL,
    `next_path` VARCHAR(255) DEFAULT NULL,
    `expires_at` DATETIME NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_oauth_state` (`provider`, `state`),
    INDEX `idx_oauth_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
