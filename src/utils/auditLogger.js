const pool = require("../config/db")

async function logAction({ actor, action, targetType = null, targetId = null, metadata = null }) {
    try {
        await pool.query(
            `
                INSERT INTO mdt_audit_logs (actor_id, actor_username, action, target_type, target_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            `,
            [
                actor?.id || null,
                actor?.username || "system",
                action,
                targetType,
                targetId,
                metadata ? JSON.stringify(metadata) : null
            ]
        )
    } catch (error) {
        console.error("MDT audit log failed", error)
    }
}

module.exports = logAction
