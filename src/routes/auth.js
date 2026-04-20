const express = require("express")
const bcrypt = require("bcrypt")
const crypto = require("crypto")
const jwt = require("jsonwebtoken")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const { getUserAccessProfile } = require("../utils/accessControl")
const { getClientIp } = require("../utils/clientIp")
const { sendDirectMessage } = require("../services/discord")
const { getApiKey: getBridgeApiKey } = require("../services/resourceBridge")
const { normalizeDiscordId } = require("../utils/discordId")

const router = express.Router()
const LOGIN_MAX_FAILED_ATTEMPTS = Number(process.env.LOGIN_MAX_FAILED_ATTEMPTS || 5)
const LOGIN_IP_BLACKLIST_HOURS = Number(process.env.LOGIN_IP_BLACKLIST_HOURS || 12)
const PASSWORD_RESET_CODEWORD_MINUTES = Number(process.env.PASSWORD_RESET_CODEWORD_MINUTES || 5)
const DUMMY_PASSWORD_HASH = "$2b$10$4gGBO6n6N8A1N7l0SxW0se6eNrqBJ38qRAjPR9U1FVLtZL1NVr7Di"
const PASSWORD_RESET_WORDS = [
    "amber", "anchor", "atlas", "baker", "bandit", "blizzard", "bravo", "canyon", "carbon", "cedar",
    "comet", "copper", "delta", "echo", "ember", "falcon", "frost", "harbor", "hazel", "helios",
    "indigo", "jade", "keystone", "lagoon", "lancer", "lotus", "matrix", "nova", "onyx", "orbit",
    "phoenix", "quartz", "ranger", "raven", "rocket", "sable", "summit", "tempo", "thunder", "vortex"
]

function invalidCredentials(res) {
    return res.status(401).json({ error: "Invalid credentials" })
}

function generateResetCodeword() {
    const firstWord = PASSWORD_RESET_WORDS[crypto.randomInt(0, PASSWORD_RESET_WORDS.length)]
    const secondWord = PASSWORD_RESET_WORDS[crypto.randomInt(0, PASSWORD_RESET_WORDS.length)]
    const suffix = crypto.randomInt(100, 1000)
    return `${firstWord}-${secondWord}-${suffix}`
}

function normalizeResetCodeword(value) {
    return String(value || "").trim().toLowerCase()
}

function normalizeCitizenId(value) {
    const citizenId = String(value || "").trim()
    return citizenId || null
}

function normalizeFiveMRole(value) {
    const normalized = String(value || "").trim().toLowerCase()
    if (["admin", "superadmin"].includes(normalized)) {
        return normalized
    }

    return "user"
}

function buildFiveMUsername(citizenId) {
    return String(citizenId || "").trim()
}

function buildFiveMDisplayName(firstName, lastName, fallbackValue) {
    const normalizedFirstName = String(firstName || "").trim()
    const normalizedLastName = String(lastName || "").trim()
    const fullName = [normalizedFirstName, normalizedLastName].filter(Boolean).join(" ").trim()
    return fullName || String(fallbackValue || "").trim()
}

async function getSharedDiscordIdForUser(userId) {
    if (!userId) {
        return null
    }

    const [rows] = await pool.query(
        `
            SELECT discord
            FROM users
            WHERE userId = ?
            LIMIT 1
        `,
        [userId]
    )

    return normalizeDiscordId(rows[0]?.discord || null)
}

async function getFirstRankForGroupName(groupName) {
    if (!groupName) {
        return null
    }

    const [rows] = await pool.query(
        `
            SELECT groups.id AS group_id, ranks.id AS rank_id
            FROM mdt_groups AS groups
            INNER JOIN mdt_group_ranks AS ranks
                ON ranks.group_id = groups.id
            WHERE groups.name = ?
            ORDER BY ranks.sort_order ASC, ranks.id ASC
            LIMIT 1
        `,
        [groupName]
    )

    return rows[0] || null
}

async function replaceUserMembershipsForGroupName(userId, groupName) {
    const firstRank = await getFirstRankForGroupName(groupName)
    if (!firstRank) {
        return false
    }

    const connection = await pool.getConnection()

    try {
        await connection.beginTransaction()
        await connection.query("DELETE FROM mdt_user_group_memberships WHERE user_id = ?", [userId])
        await connection.query(
            `
                INSERT INTO mdt_user_group_memberships (user_id, group_id, rank_id, is_active)
                VALUES (?, ?, ?, 1)
            `,
            [userId, firstRank.group_id, firstRank.rank_id]
        )
        await connection.commit()
    } catch (error) {
        await connection.rollback()
        throw error
    } finally {
        connection.release()
    }

    return true
}

async function getTrustedFiveMToken() {
    const configuredToken = process.env.MDT_FIVEM_RESOURCE_TOKEN?.trim()
    if (configuredToken) {
        return configuredToken
    }

    return getBridgeApiKey()
}

async function isTrustedFiveMRequest(req) {
    const authorization = String(req.headers?.authorization || "")
    const bearerToken = authorization.match(/^Bearer\s+(.+)$/i)?.[1]?.trim()
    if (!bearerToken) {
        return false
    }

    const trustedToken = await getTrustedFiveMToken()
    return Boolean(trustedToken && bearerToken === trustedToken)
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
    console.log("[MDT Auth] /auth/me resolved", {
        userId: req.user?.id ?? null,
        username: req.user?.username ?? null,
        citizenid: req.user?.citizenid ?? null,
        role: req.user?.role ?? null
    })

    res.json({
        user: req.user
    })
})

router.post("/fivem/session", async (req, res) => {
    try {
        const isTrusted = await isTrustedFiveMRequest(req)
        if (!isTrusted) {
            console.warn("[MDT Auth] Rejected untrusted FiveM session request")
            return res.status(403).json({ error: "Forbidden" })
        }

        const citizenid = normalizeCitizenId(req.body?.citizenid)
        const userId = Number.parseInt(req.body?.userId, 10)
        const requestedRole = normalizeFiveMRole(req.body?.role)
        const mappedGroupName = String(req.body?.mdtGroup || "").trim() || null
        const firstName = String(req.body?.firstname || "").trim()
        const lastName = String(req.body?.lastname || "").trim()

        console.log("[MDT Auth] FiveM session request", {
            citizenid,
            userId,
            requestedRole,
            mappedGroupName,
            firstName,
            lastName
        })

        if (!citizenid) {
            return res.status(400).json({ error: "Citizen ID is required" })
        }

        const username = buildFiveMUsername(citizenid)
        const displayName = buildFiveMDisplayName(firstName, lastName, username)
        const discordId = await getSharedDiscordIdForUser(userId)
        const [existingRows] = await pool.query(
            `
                SELECT id, username, role
                FROM mdt_users
                WHERE citizenid = ?
                LIMIT 1
            `,
            [citizenid]
        )

        let userIdForSession = Number(existingRows[0]?.id || 0)
        if (!userIdForSession) {
            console.warn("[MDT Auth] Rejected FiveM session for missing MDT user", {
                username,
                displayName,
                citizenid,
                requestedRole,
                discordId
            })
            return res.status(403).json({
                error: "No MDT account exists for this character. Ask an MDT admin to create or link the account first."
            })
        } else {
            await pool.query(
                `
                    UPDATE mdt_users
                    SET is_active = 1,
                        username = CASE
                            WHEN username = ? OR username = ?
                                THEN ?
                            ELSE username
                        END,
                        display_name = ?,
                        discord_id = COALESCE(?, discord_id),
                        citizenid = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `,
                [buildFiveMUsername(citizenid), `fivem-${String(citizenid || "").trim().toLowerCase()}`, buildFiveMUsername(citizenid), displayName, discordId, citizenid, userIdForSession]
            )

            console.log("[MDT Auth] Reused MDT user for FiveM session", {
                userId: userIdForSession,
                username,
                displayName,
                citizenid,
                discordId
            })
        }

        if (mappedGroupName) {
            const membershipApplied = await replaceUserMembershipsForGroupName(userIdForSession, mappedGroupName)
            console.log("[MDT Auth] Applied mapped MDT group", {
                userId: userIdForSession,
                mappedGroupName,
                membershipApplied
            })
        }

        await pool.query(
            `
                UPDATE mdt_users
                SET last_login_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `,
            [userIdForSession]
        )

        const accessProfile = await getUserAccessProfile(userIdForSession)
        if (!accessProfile) {
            return res.status(500).json({ error: "Unable to create MDT session" })
        }

        console.log("[MDT Auth] FiveM session resolved access profile", {
            userId: accessProfile.id,
            username: accessProfile.username,
            citizenid: accessProfile.citizenid,
            role: accessProfile.role
        })

        const token = jwt.sign(
            {
                id: Number(accessProfile.id),
                username: accessProfile.username,
                role: accessProfile.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRES_IN || "12h"
            }
        )

        return res.json({
            token,
            user: accessProfile
        })
    } catch (error) {
        console.error(error)
        return res.status(500).json({ error: "Server Error" })
    }
})

router.post("/password-reset/request", async (req, res) => {
    try {
        const username = String(req.body?.username || "").trim()
        if (!username) {
            return res.status(400).json({ error: "Username is required" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, username, discord_id, is_active
                FROM mdt_users
                WHERE username = ?
                LIMIT 1
            `,
            [username]
        )

        const user = rows[0]
        const genericResponse = {
            success: true,
            message: "If that account is eligible, a reset code has been sent through Discord."
        }

        if (!user || !user.is_active || !user.discord_id) {
            return res.json(genericResponse)
        }

        const codeword = generateResetCodeword()
        const expiresAt = new Date(Date.now() + (PASSWORD_RESET_CODEWORD_MINUTES * 60 * 1000))

        await pool.query(
            `
                UPDATE mdt_users
                SET reset_passphrase = ?, reset_passphrase_expires_at = ?
                WHERE id = ?
            `,
            [codeword, expiresAt, user.id]
        )

        try {
            await sendDirectMessage(
                user.discord_id,
                [
                    "Pure Roleplay MDT password reset",
                    `Codeword: ${codeword}`,
                    `This expires in ${PASSWORD_RESET_CODEWORD_MINUTES} minute${PASSWORD_RESET_CODEWORD_MINUTES === 1 ? "" : "s"}.`,
                    "If you did not request this, you can ignore this message."
                ].join("\n")
            )
        } catch (discordError) {
            await pool.query(
                `
                    UPDATE mdt_users
                    SET reset_passphrase = NULL,
                        reset_passphrase_expires_at = NULL
                    WHERE id = ?
                `,
                [user.id]
            )
            console.error("Failed to send password reset Discord DM", discordError)
            return res.status(500).json({
                error: "Unable to send the reset code through Discord right now."
            })
        }

        return res.json(genericResponse)
    } catch (error) {
        console.error(error)
        return res.status(500).json({ error: "Server Error" })
    }
})

router.post("/password-reset/confirm", async (req, res) => {
    try {
        const username = String(req.body?.username || "").trim()
        const codeword = normalizeResetCodeword(req.body?.codeword)
        const newPassword = String(req.body?.newPassword || "")

        if (!username || !codeword || !newPassword) {
            return res.status(400).json({ error: "Username, codeword, and new password are required" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, is_active, reset_passphrase, reset_passphrase_expires_at
                FROM mdt_users
                WHERE username = ?
                LIMIT 1
            `,
            [username]
        )

        const user = rows[0]
        const storedCodeword = normalizeResetCodeword(user?.reset_passphrase)
        const expiresAt = user?.reset_passphrase_expires_at ? new Date(user.reset_passphrase_expires_at) : null

        if (
            !user
            || !user.is_active
            || !storedCodeword
            || storedCodeword !== codeword
            || !expiresAt
            || expiresAt <= new Date()
        ) {
            return res.status(400).json({ error: "The reset codeword is invalid or has expired" })
        }

        const passwordHash = await bcrypt.hash(newPassword, 10)
        await pool.query(
            `
                UPDATE mdt_users
                SET password_hash = ?,
                    reset_passphrase = NULL,
                    reset_passphrase_expires_at = NULL
                WHERE id = ?
            `,
            [passwordHash, user.id]
        )

        return res.json({
            success: true,
            message: "Password reset successfully. You can sign in with the new password now."
        })
    } catch (error) {
        console.error(error)
        return res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
