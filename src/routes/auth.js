const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const { getUserAccessProfile } = require("../utils/accessControl")
const { getClientIp } = require("../utils/clientIp")

const router = express.Router()
const LOGIN_MAX_FAILED_ATTEMPTS = Number(process.env.LOGIN_MAX_FAILED_ATTEMPTS || 5)
const LOGIN_IP_BLACKLIST_HOURS = Number(process.env.LOGIN_IP_BLACKLIST_HOURS || 12)
const DUMMY_PASSWORD_HASH = "$2b$10$4gGBO6n6N8A1N7l0SxW0se6eNrqBJ38qRAjPR9U1FVLtZL1NVr7Di"

function invalidCredentials(res) {
    return res.status(401).json({ error: "Invalid credentials" })
}

async function getBlacklistEntry(ipAddress) {
    const [rows] = await pool.query(
        `
            SELECT id, ip_address, failed_attempts, first_failed_at, last_failed_at, blacklisted_until
            FROM api_ip_blacklist
            WHERE ip_address = ?
            LIMIT 1
        `,
        [ipAddress]
    )

    return rows[0] || null
}

async function registerFailedLoginAttempt(ipAddress) {
    if (!ipAddress) {
        return null
    }

    const existingEntry = await getBlacklistEntry(ipAddress)
    const now = new Date()
    const existingBlacklistExpiry = existingEntry?.blacklisted_until ? new Date(existingEntry.blacklisted_until) : null
    const hasActiveBlacklist = existingBlacklistExpiry && existingBlacklistExpiry > now
    const hasExpiredBlacklist = existingBlacklistExpiry && existingBlacklistExpiry <= now
    const nextFailedAttempts = hasActiveBlacklist
        ? Number(existingEntry.failed_attempts || 0)
        : hasExpiredBlacklist
            ? 1
            : Number(existingEntry?.failed_attempts || 0) + 1
    const shouldBlacklist = nextFailedAttempts >= LOGIN_MAX_FAILED_ATTEMPTS
    const blacklistedUntil = shouldBlacklist
        ? new Date(now.getTime() + (LOGIN_IP_BLACKLIST_HOURS * 60 * 60 * 1000))
        : null

    await pool.query(
        `
            INSERT INTO api_ip_blacklist (
                ip_address,
                failed_attempts,
                first_failed_at,
                last_failed_at,
                blacklisted_until,
                reason
            )
            VALUES (
                ?,
                ?,
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP,
                ?,
                ?
            )
            ON DUPLICATE KEY UPDATE
                failed_attempts = VALUES(failed_attempts),
                first_failed_at = IF(VALUES(failed_attempts) = 1, CURRENT_TIMESTAMP, COALESCE(first_failed_at, CURRENT_TIMESTAMP)),
                last_failed_at = CURRENT_TIMESTAMP,
                blacklisted_until = VALUES(blacklisted_until),
                reason = VALUES(reason)
        `,
        [
            ipAddress,
            nextFailedAttempts,
            blacklistedUntil,
            shouldBlacklist ? "Too many failed login attempts" : null
        ]
    )

    return getBlacklistEntry(ipAddress)
}

async function clearFailedLoginAttempts(ipAddress) {
    if (!ipAddress) {
        return
    }

    await pool.query(
        `
            DELETE FROM api_ip_blacklist
            WHERE ip_address = ?
        `,
        [ipAddress]
    )
}

router.post("/login", async (req, res) => {
    try {
        const clientIp = getClientIp(req)
        const username = String(req.body?.username || "").trim()
        const password = String(req.body?.password || "")
        const blacklistEntry = clientIp ? await getBlacklistEntry(clientIp) : null

        if (blacklistEntry?.blacklisted_until && new Date(blacklistEntry.blacklisted_until) > new Date()) {
            return res.status(403).json({
                error: "Too many failed login attempts. Try again later.",
                blacklistedUntil: blacklistEntry.blacklisted_until
            })
        }

        if (!username || !password) {
            await registerFailedLoginAttempt(clientIp)
            return res.status(400).json({ error: "Username and password are required" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, username, password_hash, role, is_active
                FROM mdt_users
                WHERE username = ?
                LIMIT 1
            `,
            [username]
        )

        const user = rows[0]
        if (!user || !user.is_active) {
            await bcrypt.compare(password, DUMMY_PASSWORD_HASH)
            const updatedEntry = await registerFailedLoginAttempt(clientIp)
            if (updatedEntry?.blacklisted_until && new Date(updatedEntry.blacklisted_until) > new Date()) {
                return res.status(403).json({
                    error: "Too many failed login attempts. Try again later.",
                    blacklistedUntil: updatedEntry.blacklisted_until
                })
            }

            return invalidCredentials(res)
        }

        const isValid = await bcrypt.compare(password, user.password_hash)
        if (!isValid) {
            const updatedEntry = await registerFailedLoginAttempt(clientIp)
            if (updatedEntry?.blacklisted_until && new Date(updatedEntry.blacklisted_until) > new Date()) {
                return res.status(403).json({
                    error: "Too many failed login attempts. Try again later.",
                    blacklistedUntil: updatedEntry.blacklisted_until
                })
            }

            return invalidCredentials(res)
        }

        await clearFailedLoginAttempts(clientIp)

        await pool.query(
            "UPDATE mdt_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?",
            [user.id]
        )

        const token = jwt.sign(
            {
                id: Number(user.id),
                username: user.username,
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRES_IN || "12h"
            }
        )

        return res.json({
            token,
            user: await getUserAccessProfile(user.id)
        })
    } catch (error) {
        console.error(error)
        return res.status(500).json({ error: "Server Error" })
    }
})

router.get("/me", auth, async (req, res) => {
    res.json({
        user: req.user
    })
})

module.exports = router
