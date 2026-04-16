const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const logAction = require("../utils/auditLogger")

const router = express.Router()
const ALLOWED_BADGE_COLORS = new Set(["neutral", "red", "green", "yellow", "orange"])

function buildEvidenceTag() {
    return `EVD-${Date.now()}`
}

function isDiscordUrl(value) {
    if (!value) {
        return false
    }

    try {
        const parsed = new URL(value)
        const hostname = String(parsed.hostname || "").toLowerCase()
        return (
            hostname.includes("discord.gg")
            || hostname.includes("discord.com")
            || hostname.includes("discordapp.com")
            || hostname.includes("discordapp.net")
            || hostname.includes("discord.media")
        )
    } catch (_error) {
        return false
    }
}

async function getNextBadgeNumber() {
    const [rows] = await pool.query(
        `
            SELECT COALESCE(MAX(badge_number), 0) + 1 AS nextBadgeNumber
            FROM mdt_evidence
        `
    )

    return Number(rows[0]?.nextBadgeNumber || 1)
}

router.get("/", auth, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
                SELECT id, evidence_tag, badge_number, badge_color, evidence_type, title, description, image_url, citizenid, vehicle_plate, incident_id, metadata, author_username, created_at
                FROM mdt_evidence
                ORDER BY created_at DESC
                LIMIT 100
            `
        )

        res.json({ evidence: rows })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/", auth, async (req, res) => {
    try {
        const title = String(req.body?.title || "").trim()
        const evidenceType = String(req.body?.evidenceType || "").trim().toLowerCase()
        const imageUrl = String(req.body?.imageUrl || "").trim()
        const badgeColor = String(req.body?.badgeColor || "neutral").trim().toLowerCase()

        if (!title || !evidenceType) {
            return res.status(400).json({ error: "Title and evidence type are required" })
        }

        if (imageUrl && isDiscordUrl(imageUrl)) {
            return res.status(400).json({ error: "Discord-hosted image links are not allowed." })
        }

        if (imageUrl) {
            try {
                new URL(imageUrl)
            } catch (_error) {
                return res.status(400).json({ error: "Image link must be a valid URL." })
            }
        }

        if (!ALLOWED_BADGE_COLORS.has(badgeColor)) {
            return res.status(400).json({ error: "Invalid badge color." })
        }

        const evidenceTag = buildEvidenceTag()
        const badgeNumber = await getNextBadgeNumber()
        await pool.query(
            `
                INSERT INTO mdt_evidence (
                    evidence_tag, badge_number, badge_color, evidence_type, title, description, image_url, citizenid, vehicle_plate, incident_id, metadata, author_id, author_username
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
                evidenceTag,
                badgeNumber,
                badgeColor,
                evidenceType,
                title,
                String(req.body?.description || "").trim() || null,
                imageUrl || null,
                String(req.body?.citizenid || "").trim() || null,
                String(req.body?.vehiclePlate || "").trim() || null,
                req.body?.incidentId ? Number(req.body.incidentId) : null,
                req.body?.metadata ? JSON.stringify(req.body.metadata) : null,
                req.user.id,
                req.user.username
            ]
        )

        await logAction({
            actor: req.user,
            action: "EVIDENCE_CREATED",
            targetType: "evidence",
            targetId: evidenceTag
        })

        res.json({
            success: true,
            evidence: {
                evidenceTag,
                badgeNumber,
                badgeColor,
                title
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
