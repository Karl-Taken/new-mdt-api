const bcrypt = require("bcrypt")
const pool = require("../config/db")

const TABLES_SQL = [
    `
        CREATE TABLE IF NOT EXISTS mdt_users (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            username VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user',
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            discord_id VARCHAR(32) DEFAULT NULL,
            citizenid VARCHAR(64) DEFAULT NULL,
            display_name VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            last_login_at TIMESTAMP NULL DEFAULT NULL,
            reset_passphrase VARCHAR(100) DEFAULT NULL,
            reset_passphrase_expires_at DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_users_username (username),
            KEY idx_mdt_users_role (role),
            KEY idx_mdt_users_is_active (is_active),
            KEY idx_mdt_users_discord_id (discord_id),
            KEY idx_mdt_users_citizenid (citizenid),
            KEY idx_mdt_users_reset_passphrase_expires_at (reset_passphrase_expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_service_keys (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            service_name VARCHAR(64) NOT NULL,
            api_key VARCHAR(255) NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_service_keys_service_name (service_name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_groups (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            name VARCHAR(100) NOT NULL,
            description VARCHAR(255) DEFAULT NULL,
            permissions JSON DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_groups_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_tabs (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            tab_key VARCHAR(100) NOT NULL,
            label VARCHAR(100) NOT NULL,
            path VARCHAR(255) NOT NULL,
            template_type VARCHAR(50) NOT NULL,
            group_id INT UNSIGNED DEFAULT NULL,
            icon_key VARCHAR(50) DEFAULT NULL,
            is_system TINYINT(1) NOT NULL DEFAULT 0,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            sort_order INT UNSIGNED NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_tabs_tab_key (tab_key),
            UNIQUE KEY uq_mdt_tabs_path (path),
            KEY idx_mdt_tabs_group_id (group_id),
            KEY idx_mdt_tabs_template_type (template_type),
            KEY idx_mdt_tabs_sort_order (sort_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_tab_rank_permissions (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            tab_id INT UNSIGNED NOT NULL,
            group_id INT UNSIGNED NOT NULL,
            rank_id INT UNSIGNED NOT NULL,
            can_view TINYINT(1) NOT NULL DEFAULT 0,
            can_edit TINYINT(1) NOT NULL DEFAULT 0,
            can_manage TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_tab_rank_permissions_tab_rank (tab_id, rank_id),
            KEY idx_mdt_tab_rank_permissions_group_id (group_id),
            KEY idx_mdt_tab_rank_permissions_rank_id (rank_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_group_ranks (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            group_id INT UNSIGNED NOT NULL,
            name VARCHAR(100) NOT NULL,
            permissions JSON DEFAULT NULL,
            sort_order INT UNSIGNED NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_group_ranks_group_name (group_id, name),
            KEY idx_mdt_group_ranks_group_id (group_id),
            KEY idx_mdt_group_ranks_sort_order (sort_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_user_group_memberships (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id INT UNSIGNED NOT NULL,
            group_id INT UNSIGNED NOT NULL,
            rank_id INT UNSIGNED NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_user_group_memberships_user_group (user_id, group_id),
            KEY idx_mdt_user_group_memberships_rank_id (rank_id),
            KEY idx_mdt_user_group_memberships_is_active (is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS api_ip_blacklist (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(64) NOT NULL,
            failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
            first_failed_at TIMESTAMP NULL DEFAULT NULL,
            last_failed_at TIMESTAMP NULL DEFAULT NULL,
            blacklisted_until DATETIME DEFAULT NULL,
            reason VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_api_ip_blacklist_ip_address (ip_address),
            KEY idx_api_ip_blacklist_blacklisted_until (blacklisted_until)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_audit_logs (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            actor_id INT UNSIGNED DEFAULT NULL,
            actor_username VARCHAR(255) NOT NULL,
            action VARCHAR(100) NOT NULL,
            target_type VARCHAR(64) DEFAULT NULL,
            target_id VARCHAR(255) DEFAULT NULL,
            metadata JSON DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_audit_logs_action (action),
            KEY idx_mdt_audit_logs_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_announcements (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            title VARCHAR(255) NOT NULL,
            body MEDIUMTEXT NOT NULL,
            priority VARCHAR(32) NOT NULL DEFAULT 'normal',
            author_id INT UNSIGNED DEFAULT NULL,
            author_username VARCHAR(255) NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_announcements_priority (priority),
            KEY idx_mdt_announcements_is_active (is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_penal_code_charges (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            title VARCHAR(255) NOT NULL,
            code VARCHAR(64) DEFAULT NULL,
            category VARCHAR(100) DEFAULT NULL,
            class VARCHAR(100) DEFAULT NULL,
            fine INT UNSIGNED NOT NULL DEFAULT 0,
            jail_time INT UNSIGNED NOT NULL DEFAULT 0,
            points SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            description TEXT DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_penal_code_charges_title (title),
            KEY idx_mdt_penal_code_charges_category (category)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_penal_code_categories (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            name VARCHAR(100) NOT NULL,
            kind VARCHAR(20) NOT NULL DEFAULT 'title',
            sort_order INT UNSIGNED NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_penal_code_categories_name (name),
            KEY idx_mdt_penal_code_categories_kind (kind),
            KEY idx_mdt_penal_code_categories_sort_order (sort_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_penal_code_definitions (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            category_id INT UNSIGNED NOT NULL,
            code VARCHAR(64) NOT NULL,
            name VARCHAR(255) NOT NULL,
            definition TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_penal_code_definitions_category_code (category_id, code),
            KEY idx_mdt_penal_code_definitions_category_id (category_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_penal_code_charge_enhancements (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            charge_id INT UNSIGNED NOT NULL,
            label VARCHAR(100) NOT NULL,
            color VARCHAR(20) NOT NULL DEFAULT 'neutral',
            fine_percent_off DECIMAL(5,2) NOT NULL DEFAULT 0.00,
            jail_percent_off DECIMAL(5,2) NOT NULL DEFAULT 0.00,
            display_order SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_penal_code_charge_enhancements_charge_id (charge_id),
            KEY idx_mdt_penal_code_charge_enhancements_display_order (display_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_character_profiles (
            citizenid VARCHAR(64) NOT NULL,
            image_url VARCHAR(2048) DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (citizenid)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_character_notes (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            citizenid VARCHAR(64) NOT NULL,
            note TEXT NOT NULL,
            author_id INT UNSIGNED DEFAULT NULL,
            author_username VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_character_notes_citizenid (citizenid),
            KEY idx_mdt_character_notes_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_character_flags (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            citizenid VARCHAR(64) NOT NULL,
            flag_type VARCHAR(50) NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT DEFAULT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            expires_at TIMESTAMP NULL DEFAULT NULL,
            author_id INT UNSIGNED DEFAULT NULL,
            author_username VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_character_flags_citizenid (citizenid),
            KEY idx_mdt_character_flags_flag_type (flag_type),
            KEY idx_mdt_character_flags_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_character_vehicles (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            citizenid VARCHAR(64) NOT NULL,
            vehicle_label VARCHAR(255) NOT NULL,
            plate VARCHAR(32) DEFAULT NULL,
            notes TEXT DEFAULT NULL,
            author_id INT UNSIGNED DEFAULT NULL,
            author_username VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_character_vehicles_citizenid (citizenid),
            KEY idx_mdt_character_vehicles_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_incidents (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            incident_number VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            summary TEXT DEFAULT NULL,
            narrative MEDIUMTEXT DEFAULT NULL,
            location VARCHAR(255) DEFAULT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'open',
            occurred_at DATETIME DEFAULT NULL,
            author_id INT UNSIGNED DEFAULT NULL,
            author_username VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_incidents_incident_number (incident_number),
            KEY idx_mdt_incidents_status (status),
            KEY idx_mdt_incidents_occurred_at (occurred_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_incident_drafts (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            draft_key VARCHAR(128) NOT NULL,
            incident_id INT UNSIGNED DEFAULT NULL,
            payload LONGTEXT NOT NULL,
            revision INT UNSIGNED NOT NULL DEFAULT 1,
            last_editor_id INT UNSIGNED DEFAULT NULL,
            last_editor_username VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_incident_drafts_draft_key (draft_key),
            KEY idx_mdt_incident_drafts_incident_id (incident_id),
            KEY idx_mdt_incident_drafts_updated_at (updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_incident_draft_presence (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            draft_key VARCHAR(128) NOT NULL,
            editor_key VARCHAR(128) NOT NULL,
            user_id INT UNSIGNED NOT NULL,
            username VARCHAR(255) NOT NULL,
            cursor_json TEXT DEFAULT NULL,
            color VARCHAR(32) DEFAULT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_incident_draft_presence_user (draft_key, editor_key, user_id),
            KEY idx_mdt_incident_draft_presence_lookup (draft_key, editor_key, updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_incident_people (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            incident_id INT UNSIGNED NOT NULL,
            citizenid VARCHAR(64) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'subject',
            notes TEXT DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_incident_people_incident_id (incident_id),
            KEY idx_mdt_incident_people_citizenid (citizenid)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_incident_officers (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            incident_id INT UNSIGNED NOT NULL,
            officer_name VARCHAR(255) NOT NULL,
            callsign VARCHAR(64) DEFAULT NULL,
            role VARCHAR(64) DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_incident_officers_incident_id (incident_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_incident_reports (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            incident_id INT UNSIGNED NOT NULL,
            title VARCHAR(255) NOT NULL,
            report_type VARCHAR(100) DEFAULT NULL,
            report_html MEDIUMTEXT DEFAULT NULL,
            report_text MEDIUMTEXT DEFAULT NULL,
            display_order SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            author_id INT UNSIGNED DEFAULT NULL,
            author_username VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_incident_reports_incident_id (incident_id),
            KEY idx_mdt_incident_reports_display_order (display_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_incident_charges (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            incident_id INT UNSIGNED NOT NULL,
            citizenid VARCHAR(64) NOT NULL,
            charge_id INT UNSIGNED DEFAULT NULL,
            charge_title VARCHAR(255) NOT NULL,
            count SMALLINT UNSIGNED NOT NULL DEFAULT 1,
            fine INT UNSIGNED NOT NULL DEFAULT 0,
            jail_time INT UNSIGNED NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_incident_charges_incident_id (incident_id),
            KEY idx_mdt_incident_charges_citizenid (citizenid)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_roster_entries (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            tab_id INT UNSIGNED NOT NULL,
            user_id INT UNSIGNED DEFAULT NULL,
            citizenid VARCHAR(64) DEFAULT NULL,
            display_name VARCHAR(255) NOT NULL,
            rank_label VARCHAR(100) DEFAULT NULL,
            unit_label VARCHAR(100) DEFAULT NULL,
            notes TEXT DEFAULT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_mdt_roster_entries_tab_id (tab_id),
            KEY idx_mdt_roster_entries_user_id (user_id),
            KEY idx_mdt_roster_entries_citizenid (citizenid)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
        CREATE TABLE IF NOT EXISTS mdt_evidence (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            evidence_tag VARCHAR(64) NOT NULL,
            badge_number INT UNSIGNED NOT NULL,
            badge_color VARCHAR(20) NOT NULL DEFAULT 'neutral',
            evidence_type VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT DEFAULT NULL,
            image_url VARCHAR(2048) DEFAULT NULL,
            citizenid VARCHAR(64) DEFAULT NULL,
            vehicle_plate VARCHAR(32) DEFAULT NULL,
            incident_id INT UNSIGNED DEFAULT NULL,
            metadata JSON DEFAULT NULL,
            author_id INT UNSIGNED DEFAULT NULL,
            author_username VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mdt_evidence_evidence_tag (evidence_tag),
            UNIQUE KEY uq_mdt_evidence_badge_number (badge_number),
            KEY idx_mdt_evidence_citizenid (citizenid),
            KEY idx_mdt_evidence_vehicle_plate (vehicle_plate),
            KEY idx_mdt_evidence_incident_id (incident_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `
]

async function ensureBootstrapAdmin() {
    const username = process.env.MDT_BOOTSTRAP_ADMIN_USERNAME?.trim()
    const password = process.env.MDT_BOOTSTRAP_ADMIN_PASSWORD?.trim()
    if (!username || !password) {
        return
    }

    const [rows] = await pool.query(
        "SELECT id FROM mdt_users WHERE username = ? LIMIT 1",
        [username]
    )

    if (rows.length) {
        return
    }

    const passwordHash = await bcrypt.hash(password, 10)
    await pool.query(
        `
            INSERT INTO mdt_users (username, password_hash, role)
            VALUES (?, ?, 'superadmin')
        `,
        [username, passwordHash]
    )
}

async function ensureUserRoleDefaults() {
    await pool.query(
        `
            UPDATE mdt_users
            SET role = 'user'
            WHERE role IN ('officer', 'law_enforcement')
        `
    )

    const [roleRows] = await pool.query("SHOW COLUMNS FROM mdt_users LIKE 'role'")
    const roleColumn = roleRows[0]
    if (!roleColumn) {
        return
    }

    if (String(roleColumn.Default || "").trim().toLowerCase() !== "user") {
        await pool.query(
            `
                ALTER TABLE mdt_users
                MODIFY COLUMN role VARCHAR(50) NOT NULL DEFAULT 'user'
            `
        )
    }
}

async function ensureUserSecurityColumns() {
    const expectedColumns = [
        {
            columnName: "discord_id",
            definition: "VARCHAR(32) DEFAULT NULL AFTER is_active"
        },
        {
            columnName: "citizenid",
            definition: "VARCHAR(64) DEFAULT NULL AFTER discord_id"
        },
        {
            columnName: "display_name",
            definition: "VARCHAR(255) DEFAULT NULL AFTER citizenid"
        },
        {
            columnName: "reset_passphrase",
            definition: "VARCHAR(100) DEFAULT NULL AFTER last_login_at"
        },
        {
            columnName: "reset_passphrase_expires_at",
            definition: "DATETIME DEFAULT NULL AFTER reset_passphrase"
        }
    ]

    for (const column of expectedColumns) {
        const [rows] = await pool.query("SHOW COLUMNS FROM mdt_users LIKE ?", [column.columnName])
        if (!rows.length) {
            await pool.query(
                `
                    ALTER TABLE mdt_users
                    ADD COLUMN ${column.columnName} ${column.definition}
                `
            )
        }
    }

    const expectedIndexes = [
        {
            indexName: "idx_mdt_users_discord_id",
            definition: "(discord_id)"
        },
        {
            indexName: "idx_mdt_users_citizenid",
            definition: "(citizenid)"
        },
        {
            indexName: "idx_mdt_users_reset_passphrase_expires_at",
            definition: "(reset_passphrase_expires_at)"
        }
    ]

    for (const index of expectedIndexes) {
        const [rows] = await pool.query("SHOW INDEX FROM mdt_users WHERE Key_name = ?", [index.indexName])
        if (!rows.length) {
            await pool.query(
                `
                    ALTER TABLE mdt_users
                    ADD KEY ${index.indexName} ${index.definition}
                `
            )
        }
    }

    await pool.query(
        `
            UPDATE mdt_users
            SET discord_id = NULL
            WHERE discord_id = ''
        `
    )

    await pool.query(
        `
            UPDATE mdt_users
            SET display_name = username
            WHERE display_name IS NULL
                OR display_name = ''
        `
    )
}

async function ensureChargeCategories() {
    await pool.query(
        `
            UPDATE mdt_penal_code_categories
            SET kind = 'title'
            WHERE kind != 'title'
        `
    )

    const [rows] = await pool.query(
        `
            SELECT DISTINCT category
            FROM mdt_penal_code_charges
            WHERE category IS NOT NULL
                AND category != ''
        `
    )

    for (const row of rows) {
        await pool.query(
            `
                INSERT INTO mdt_penal_code_categories (name, kind, sort_order)
                VALUES (?, 'title', 0)
                ON DUPLICATE KEY UPDATE name = VALUES(name), kind = 'title'
            `,
            [row.category]
        )
    }
}

async function ensureChargeEnhancementColors() {
    const [rows] = await pool.query("SHOW COLUMNS FROM mdt_penal_code_charge_enhancements LIKE 'color'")
    if (!rows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_penal_code_charge_enhancements
                ADD COLUMN color VARCHAR(20) NOT NULL DEFAULT 'neutral' AFTER label
            `
        )
    }
}

async function ensureGroupPermissionsColumn() {
    const [rows] = await pool.query("SHOW COLUMNS FROM mdt_groups LIKE 'permissions'")
    if (!rows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_groups
                ADD COLUMN permissions JSON DEFAULT NULL AFTER description
            `
        )
    }
}

async function ensureChargeCategorySortOrder() {
    const [rows] = await pool.query("SHOW COLUMNS FROM mdt_penal_code_categories LIKE 'sort_order'")
    if (!rows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_penal_code_categories
                ADD COLUMN sort_order INT UNSIGNED NOT NULL DEFAULT 0 AFTER kind
            `
        )
    }

    const [categories] = await pool.query(
        `
            SELECT id
            FROM mdt_penal_code_categories
            ORDER BY sort_order ASC, name ASC
        `
    )

    let order = 1
    for (const category of categories) {
        await pool.query(
            `
                UPDATE mdt_penal_code_categories
                SET sort_order = ?
                WHERE id = ?
                    AND sort_order = 0
            `,
            [order, category.id]
        )
        order += 1
    }
}

async function ensureEvidenceBadgeColumns() {
    const [badgeNumberRows] = await pool.query("SHOW COLUMNS FROM mdt_evidence LIKE 'badge_number'")
    if (!badgeNumberRows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_evidence
                ADD COLUMN badge_number INT UNSIGNED NULL AFTER evidence_tag
            `
        )
    }

    const [badgeColorRows] = await pool.query("SHOW COLUMNS FROM mdt_evidence LIKE 'badge_color'")
    if (!badgeColorRows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_evidence
                ADD COLUMN badge_color VARCHAR(20) NOT NULL DEFAULT 'neutral' AFTER badge_number
            `
        )
    }

    const [imageUrlRows] = await pool.query("SHOW COLUMNS FROM mdt_evidence LIKE 'image_url'")
    if (!imageUrlRows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_evidence
                ADD COLUMN image_url VARCHAR(2048) DEFAULT NULL AFTER description
            `
        )
    }

    const [evidenceRows] = await pool.query(
        `
            SELECT id, badge_number
            FROM mdt_evidence
            ORDER BY id ASC
        `
    )

    let nextBadgeNumber = 1
    for (const row of evidenceRows) {
        if (!row.badge_number || Number(row.badge_number) <= 0) {
            await pool.query(
                `
                    UPDATE mdt_evidence
                    SET badge_number = ?
                    WHERE id = ?
                `,
                [nextBadgeNumber, row.id]
            )
            nextBadgeNumber += 1
            continue
        }

        nextBadgeNumber = Math.max(nextBadgeNumber, Number(row.badge_number) + 1)
    }

    const [indexes] = await pool.query("SHOW INDEX FROM mdt_evidence WHERE Key_name = 'uq_mdt_evidence_badge_number'")
    if (!indexes.length) {
        await pool.query(
            `
                ALTER TABLE mdt_evidence
                ADD UNIQUE KEY uq_mdt_evidence_badge_number (badge_number)
            `
        )
    }

    const [badgeNumberRowsAfter] = await pool.query("SHOW COLUMNS FROM mdt_evidence LIKE 'badge_number'")
    if (badgeNumberRowsAfter.length && String(badgeNumberRowsAfter[0].Null).toUpperCase() === "YES") {
        await pool.query(
            `
                ALTER TABLE mdt_evidence
                MODIFY COLUMN badge_number INT UNSIGNED NOT NULL
            `
        )
    }
}

async function ensureTabScopedColumns() {
    const tabScopedColumns = [
        {
            tableName: "mdt_incidents",
            columnName: "tab_id",
            definition: "INT UNSIGNED DEFAULT NULL AFTER status"
        },
        {
            tableName: "mdt_announcements",
            columnName: "tab_id",
            definition: "INT UNSIGNED DEFAULT NULL AFTER priority"
        }
    ]

    for (const column of tabScopedColumns) {
        const [rows] = await pool.query(`SHOW COLUMNS FROM ${column.tableName} LIKE ?`, [column.columnName])
        if (!rows.length) {
            await pool.query(
                `
                    ALTER TABLE ${column.tableName}
                    ADD COLUMN ${column.columnName} ${column.definition}
                `
            )
        }
    }
}

async function ensureTabMetadataColumns() {
    const metadataColumns = [
        {
            columnName: "hover_label",
            definition: "VARCHAR(255) DEFAULT NULL AFTER label"
        },
        {
            columnName: "roster_default_role",
            definition: "VARCHAR(50) DEFAULT NULL AFTER hover_label"
        },
        {
            columnName: "roster_default_group_id",
            definition: "INT UNSIGNED DEFAULT NULL AFTER roster_default_role"
        }
    ]

    for (const column of metadataColumns) {
        const [rows] = await pool.query("SHOW COLUMNS FROM mdt_tabs LIKE ?", [column.columnName])
        if (!rows.length) {
            await pool.query(
                `
                    ALTER TABLE mdt_tabs
                    ADD COLUMN ${column.columnName} ${column.definition}
                `
            )
        }
    }
}

async function ensureApiIpBlacklistColumns() {
    const expectedColumns = [
        {
            columnName: "failed_attempts",
            definition: "INT UNSIGNED NOT NULL DEFAULT 0 AFTER ip_address"
        },
        {
            columnName: "first_failed_at",
            definition: "TIMESTAMP NULL DEFAULT NULL AFTER failed_attempts"
        },
        {
            columnName: "last_failed_at",
            definition: "TIMESTAMP NULL DEFAULT NULL AFTER first_failed_at"
        },
        {
            columnName: "blacklisted_until",
            definition: "DATETIME DEFAULT NULL AFTER last_failed_at"
        },
        {
            columnName: "updated_at",
            definition: "TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER created_at"
        }
    ]

    for (const column of expectedColumns) {
        const [rows] = await pool.query("SHOW COLUMNS FROM api_ip_blacklist LIKE ?", [column.columnName])
        if (!rows.length) {
            await pool.query(
                `
                    ALTER TABLE api_ip_blacklist
                    ADD COLUMN ${column.columnName} ${column.definition}
                `
            )
        }
    }

    const [indexRows] = await pool.query("SHOW INDEX FROM api_ip_blacklist WHERE Key_name = 'idx_api_ip_blacklist_blacklisted_until'")
    if (!indexRows.length) {
        await pool.query(
            `
                ALTER TABLE api_ip_blacklist
                ADD KEY idx_api_ip_blacklist_blacklisted_until (blacklisted_until)
            `
        )
    }
}

async function ensureRosterRankColumn() {
    const [rows] = await pool.query("SHOW COLUMNS FROM mdt_roster_entries LIKE 'rank_id'")
    if (!rows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_roster_entries
                ADD COLUMN rank_id INT UNSIGNED DEFAULT NULL AFTER citizenid
            `
        )
    }
}

async function ensureIncidentReportTypeColumn() {
    const [rows] = await pool.query("SHOW COLUMNS FROM mdt_incident_reports LIKE 'report_type'")
    if (!rows.length) {
        await pool.query(
            `
                ALTER TABLE mdt_incident_reports
                ADD COLUMN report_type VARCHAR(100) DEFAULT NULL AFTER title
            `
        )
    }
}

async function ensureEveryoneAccessGroup() {
    await pool.query(
        `
            INSERT INTO mdt_groups (name, description, permissions)
            VALUES ('@everyone', 'Built-in default access group applied to all MDT users.', ?)
            ON DUPLICATE KEY UPDATE
                description = VALUES(description)
        `,
        [JSON.stringify([])]
    )

    const [groupRows] = await pool.query(
        "SELECT id FROM mdt_groups WHERE name = '@everyone' LIMIT 1"
    )
    const groupId = Number(groupRows[0]?.id || 0)
    if (!groupId) {
        return
    }

    await pool.query(
        `
            INSERT INTO mdt_group_ranks (group_id, name, permissions, sort_order)
            VALUES (?, 'Everyone', ?, 1)
            ON DUPLICATE KEY UPDATE
                sort_order = VALUES(sort_order)
        `,
        [groupId, JSON.stringify([])]
    )
}

async function ensureSamsMedicalReportsTab() {
    await pool.query(
        `
            INSERT INTO mdt_groups (name, description, permissions)
            VALUES ('SAMS', 'San Andreas Medical Services default access group.', ?)
            ON DUPLICATE KEY UPDATE
                description = VALUES(description)
        `,
        [JSON.stringify([])]
    )

    const [groupRows] = await pool.query("SELECT id FROM mdt_groups WHERE name = 'SAMS' LIMIT 1")
    const groupId = Number(groupRows[0]?.id || 0)
    if (!groupId) {
        return
    }

    await pool.query(
        `
            INSERT INTO mdt_group_ranks (group_id, name, permissions, sort_order)
            VALUES (?, 'Member', ?, 1)
            ON DUPLICATE KEY UPDATE
                sort_order = VALUES(sort_order)
        `,
        [groupId, JSON.stringify([])]
    )

    const [rankRows] = await pool.query(
        "SELECT id FROM mdt_group_ranks WHERE group_id = ? ORDER BY sort_order ASC, id ASC LIMIT 1",
        [groupId]
    )
    const rankId = Number(rankRows[0]?.id || 0)

    await pool.query(
        `
            INSERT INTO mdt_tabs (tab_key, label, path, template_type, group_id, icon_key, is_system, is_active, sort_order)
            VALUES ('sams-medical-reports', 'Medical Reports', '/groups/sams/medical_reports/sams-medical-reports', 'medical_reports', ?, 'medical_reports', 0, 1, 50)
            ON DUPLICATE KEY UPDATE
                label = VALUES(label),
                path = VALUES(path),
                template_type = VALUES(template_type),
                group_id = VALUES(group_id),
                icon_key = VALUES(icon_key),
                is_active = VALUES(is_active)
        `,
        [groupId]
    )

    if (!rankId) {
        return
    }

    const [tabRows] = await pool.query("SELECT id FROM mdt_tabs WHERE tab_key = 'sams-medical-reports' LIMIT 1")
    const tabId = Number(tabRows[0]?.id || 0)
    if (!tabId) {
        return
    }

    await pool.query(
        `
            INSERT INTO mdt_tab_rank_permissions (tab_id, group_id, rank_id, can_view, can_edit, can_manage)
            VALUES (?, ?, ?, 1, 1, 1)
            ON DUPLICATE KEY UPDATE
                can_view = VALUES(can_view),
                can_edit = VALUES(can_edit),
                can_manage = VALUES(can_manage)
        `,
        [tabId, groupId, rankId]
    )
}

async function cleanupLegacyEveryoneDefaultTabAccess() {
    const [groupRows] = await pool.query(
        `
            SELECT groups.id AS group_id, ranks.id AS rank_id
            FROM mdt_groups AS groups
            INNER JOIN mdt_group_ranks AS ranks
                ON ranks.group_id = groups.id
            WHERE groups.name = '@everyone'
                AND ranks.name = 'Everyone'
            LIMIT 1
        `
    )

    const everyoneGroupId = Number(groupRows[0]?.group_id || 0)
    const everyoneRankId = Number(groupRows[0]?.rank_id || 0)
    if (!everyoneGroupId || !everyoneRankId) {
        return
    }

    const [dashboardRows] = await pool.query(
        `
            SELECT id
            FROM mdt_tabs
            WHERE tab_key = 'dashboard'
            LIMIT 1
        `
    )

    const dashboardTabId = Number(dashboardRows[0]?.id || 0)
    if (!dashboardTabId) {
        return
    }

    const [permissionRows] = await pool.query(
        `
            SELECT tab_id, can_view, can_edit, can_manage
            FROM mdt_tab_rank_permissions
            WHERE group_id = ?
                AND rank_id = ?
        `,
        [everyoneGroupId, everyoneRankId]
    )

    if (
        permissionRows.length === 1 &&
        Number(permissionRows[0]?.tab_id || 0) === dashboardTabId &&
        Number(permissionRows[0]?.can_view || 0) === 1 &&
        Number(permissionRows[0]?.can_edit || 0) === 0 &&
        Number(permissionRows[0]?.can_manage || 0) === 0
    ) {
        await pool.query(
            `
                DELETE FROM mdt_tab_rank_permissions
                WHERE group_id = ?
                    AND rank_id = ?
                    AND tab_id = ?
            `,
            [everyoneGroupId, everyoneRankId, dashboardTabId]
        )
    }
}

async function ensureMdtSchema() {
    for (const sql of TABLES_SQL) {
        await pool.query(sql)
    }

    await ensureApiIpBlacklistColumns()
    await ensureUserSecurityColumns()
    await ensureChargeEnhancementColors()
    await ensureGroupPermissionsColumn()
    await ensureChargeCategorySortOrder()
    await ensureEvidenceBadgeColumns()
    await ensureTabScopedColumns()
    await ensureTabMetadataColumns()
    await ensureRosterRankColumn()
    await ensureIncidentReportTypeColumn()
    await ensureEveryoneAccessGroup()
    await ensureChargeCategories()
    await ensureChargeCategorySortOrder()
    await ensureDefaultTabs()
    await cleanupLegacyEveryoneDefaultTabAccess()
    await ensureSamsMedicalReportsTab()
    await ensureUserRoleDefaults()
    await ensureBootstrapAdmin()
}

async function ensureDefaultTabs() {
    const defaultTabs = [
        { tabKey: "dashboard", label: "Dashboard", path: "/dashboard", templateType: "dashboard", iconKey: "dashboard", isSystem: 1, sortOrder: 1 },
        { tabKey: "characters", label: "Citizen", path: "/characters", templateType: "characters", iconKey: "characters", isSystem: 1, sortOrder: 2 },
        { tabKey: "vehicles", label: "Vehicles", path: "/vehicles", templateType: "vehicles", iconKey: "vehicles", isSystem: 1, sortOrder: 3 },
        { tabKey: "incidents", label: "Incidents", path: "/incidents", templateType: "incidents", iconKey: "incidents", isSystem: 1, sortOrder: 4 },
        { tabKey: "evidence", label: "Evidence", path: "/evidence", templateType: "evidence", iconKey: "evidence", isSystem: 1, sortOrder: 5 },
        { tabKey: "charges", label: "Penal Code", path: "/charges", templateType: "charges", iconKey: "charges", isSystem: 1, sortOrder: 6 },
        { tabKey: "announcements", label: "Announcements", path: "/announcements", templateType: "announcements", iconKey: "announcements", isSystem: 1, sortOrder: 7 },
        { tabKey: "roster", label: "Roster", path: "/roster", templateType: "roster", iconKey: "roster", isSystem: 1, sortOrder: 8 }
    ]

    for (const tab of defaultTabs) {
        await pool.query(
            `
                INSERT INTO mdt_tabs (tab_key, label, path, template_type, icon_key, is_system, is_active, sort_order)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                ON DUPLICATE KEY UPDATE
                    label = VALUES(label),
                    path = VALUES(path),
                    template_type = VALUES(template_type),
                    icon_key = VALUES(icon_key),
                    is_system = VALUES(is_system),
                    sort_order = VALUES(sort_order)
            `,
            [tab.tabKey, tab.label, tab.path, tab.templateType, tab.iconKey, tab.isSystem, tab.sortOrder]
        )
    }
}

module.exports = {
    ensureMdtSchema
}
