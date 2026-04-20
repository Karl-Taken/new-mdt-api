const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const requirePermission = require("../middleware/requirePermission")
const { serializeCharacterRow, getCharacterName, safeJsonParse } = require("../utils/characters")
const { fetchOnlinePlayers } = require("../services/resourceBridge")
const logAction = require("../utils/auditLogger")
const { userHasPermission } = require("../utils/accessControl")

const router = express.Router()
const LEO_JOB_NAMES = ["sasp", "bcso"]
router.use(auth)
router.use(requirePermission("characters.view"))

function canAccessSensitiveCharacterData(user) {
    return userHasPermission(user, "characters.view")
}

function isValidImageUrl(value) {
    if (!value) {
        return true
    }

    try {
        new URL(value)
        return true
    } catch (_error) {
        return false
    }
}

router.get("/", async (req, res) => {
    try {
        const page = Math.max(parseInt(req.query.page, 10) || 1, 1)
        const requestedLimit = parseInt(req.query.limit, 10) || 20
        const limit = Math.min(Math.max(requestedLimit, 1), 100)
        const offset = (page - 1) * limit
        const search = String(req.query.search || "").trim()

        const params = []
        let whereClause = ""

        if (search) {
            const like = `%${search}%`
            whereClause = `
                WHERE p.citizenid LIKE ?
                    OR p.license LIKE ?
                    OR p.name LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.firstname")) LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.lastname")) LIKE ?
                    OR CAST(p.userId AS CHAR) LIKE ?
                    OR u.username LIKE ?
            `
            params.push(like, like, like, like, like, like, like)
        }

        const [countRows] = await pool.query(
            `
                SELECT COUNT(*) AS total
                FROM players p
                LEFT JOIN users u ON u.userId = p.userId
                ${whereClause}
            `,
            params
        )

        const [rows] = await pool.query(
            `
                SELECT p.citizenid, p.userId, p.license, p.name, p.charinfo, p.job, p.gang, p.metadata, p.last_updated, p.last_logged_out,
                       profile.image_url AS profile_image_url
                FROM players p
                LEFT JOIN users u ON u.userId = p.userId
                LEFT JOIN mdt_character_profiles profile ON profile.citizenid = p.citizenid
                ${whereClause}
                ORDER BY p.last_updated DESC, p.citizenid ASC
                LIMIT ? OFFSET ?
            `,
            [...params, limit, offset]
        )

        const onlinePlayers = await fetchOnlinePlayers()
        const onlineCitizenIds = new Set(
            onlinePlayers
                .filter((player) => player?.citizenid)
                .map((player) => player.citizenid)
        )

        const total = Number(countRows[0]?.total || 0)
        res.json({
            page,
            limit,
            total,
            totalPages: Math.max(Math.ceil(total / limit), 1),
            characters: rows.map((row) => ({
                ...serializeCharacterRow(row),
                isOnline: onlineCitizenIds.has(row.citizenid)
            }))
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/leo-search", async (req, res) => {
    try {
        const requestedLimit = parseInt(req.query.limit, 10) || 10
        const limit = Math.min(Math.max(requestedLimit, 1), 25)
        const search = String(req.query.search || "").trim()

        const params = [...LEO_JOB_NAMES]
        let whereClause = `
            WHERE LOWER(JSON_UNQUOTE(JSON_EXTRACT(p.job, "$.name"))) IN (${LEO_JOB_NAMES.map(() => "?").join(", ")})
        `

        if (search) {
            const like = `%${search}%`
            whereClause += `
                AND (
                    p.citizenid LIKE ?
                    OR p.name LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.firstname")) LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.lastname")) LIKE ?
                )
            `
            params.push(like, like, like, like)
        }

        const [rows] = await pool.query(
            `
                SELECT p.citizenid, p.userId, p.license, p.name, p.charinfo, p.job, p.gang, p.metadata, p.last_updated, p.last_logged_out,
                       profile.image_url AS profile_image_url
                FROM players p
                LEFT JOIN mdt_character_profiles profile ON profile.citizenid = p.citizenid
                ${whereClause}
                ORDER BY p.last_updated DESC, p.citizenid ASC
                LIMIT ?
            `,
            [...params, limit]
        )

        res.json({
            characters: rows.map((row) => ({
                ...serializeCharacterRow(row),
                name: getCharacterName(safeJsonParse(row.charinfo, {}), row.name)
            }))
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/roster-search", async (req, res) => {
    try {
        const requestedLimit = parseInt(req.query.limit, 10) || 25
        const limit = Math.min(Math.max(requestedLimit, 1), 100)
        const search = String(req.query.search || "").trim()
        const params = []
        let whereClause = ""

        if (search) {
            const like = `%${search}%`
            whereClause = `
                WHERE p.citizenid LIKE ?
                    OR p.name LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.firstname")) LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.lastname")) LIKE ?
                    OR CAST(p.userId AS CHAR) LIKE ?
                    OR u.username LIKE ?
            `
            params.push(like, like, like, like, like, like)
        }

        const [rows] = await pool.query(
            `
                SELECT
                    p.citizenid,
                    p.userId,
                    p.name,
                    p.charinfo,
                    p.job,
                    u.username,
                    profile.image_url AS profile_image_url
                FROM players p
                LEFT JOIN users u ON u.userId = p.userId
                LEFT JOIN mdt_character_profiles profile ON profile.citizenid = p.citizenid
                ${whereClause}
                ORDER BY p.last_updated DESC, p.citizenid ASC
                LIMIT ?
            `,
            [...params, limit]
        )

        res.json({
            characters: rows.map((row) => {
                const charinfo = safeJsonParse(row.charinfo, {})
                const job = safeJsonParse(row.job, null)

                return {
                    citizenid: row.citizenid,
                    userId: row.userId != null ? Number(row.userId) : null,
                    username: row.username || "",
                    imageUrl: row.profile_image_url || "",
                    name: getCharacterName(charinfo, row.name),
                    firstName: charinfo.firstname || "",
                    lastName: charinfo.lastname || "",
                    job
                }
            })
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/:citizenid", async (req, res) => {
    try {
        const citizenid = String(req.params.citizenid || "").trim()
        if (!citizenid) {
            return res.status(400).json({ error: "Citizen ID is required" })
        }

        const [rows] = await pool.query(
            `
                SELECT p.citizenid, p.userId, p.cid, p.license, p.name, p.money, p.charinfo, p.job, p.gang, p.position, p.metadata, p.inventory, p.last_updated, p.last_logged_out,
                       profile.image_url AS profile_image_url,
                       u.username
                FROM players p
                LEFT JOIN users u ON u.userId = p.userId
                LEFT JOIN mdt_character_profiles profile ON profile.citizenid = p.citizenid
                WHERE p.citizenid = ?
                LIMIT 1
            `,
            [citizenid]
        )

        if (!rows.length) {
            return res.status(404).json({ error: "Character not found" })
        }

        const row = rows[0]
        const charinfo = safeJsonParse(row.charinfo, {})

        const canViewSensitiveData = canAccessSensitiveCharacterData(req.user)

        const [vehicleRows, noteRows, flagRows, incidentRows, latestMugshotRows] = await Promise.all([
            canViewSensitiveData
                ? pool.query(
                    `
                        SELECT id, citizenid, vehicle_label, plate, notes, author_username, created_at, updated_at
                        FROM mdt_character_vehicles
                        WHERE citizenid = ?
                        ORDER BY created_at DESC, id DESC
                    `,
                    [citizenid]
                )
                : Promise.resolve([[]]),
            canViewSensitiveData
                ? pool.query(
                `
                    SELECT id, note, author_username, created_at
                    FROM mdt_character_notes
                    WHERE citizenid = ?
                    ORDER BY created_at DESC
                `,
                [citizenid]
            )
                : Promise.resolve([[]]),
            canViewSensitiveData
                ? pool.query(
                `
                    SELECT id, flag_type, title, description, status, expires_at, author_username, created_at
                    FROM mdt_character_flags
                    WHERE citizenid = ?
                    ORDER BY created_at DESC
                `,
                [citizenid]
            )
                : Promise.resolve([[]]),
            pool.query(
                `
                    SELECT i.id, i.incident_number, i.title, i.status, i.occurred_at
                    FROM mdt_incidents i
                    INNER JOIN mdt_incident_people p ON p.incident_id = i.id
                    WHERE p.citizenid = ?
                    ORDER BY COALESCE(i.occurred_at, i.created_at) DESC
                    LIMIT 20
                `,
                [citizenid]
            ),
            pool.query(
                `
                    SELECT evidence.image_url
                    FROM mdt_evidence evidence
                    INNER JOIN mdt_incident_people people ON people.incident_id = evidence.incident_id
                    INNER JOIN mdt_incidents incidents ON incidents.id = evidence.incident_id
                    WHERE people.citizenid = ?
                        AND evidence.image_url IS NOT NULL
                        AND evidence.image_url != ''
                    ORDER BY COALESCE(incidents.occurred_at, incidents.created_at) DESC, evidence.created_at DESC, evidence.id DESC
                    LIMIT 1
                `,
                [citizenid]
            )
        ])

        const latestIncidentMugshotUrl = latestMugshotRows[0]?.[0]?.image_url || ""

        res.json({
            character: {
                citizenid: row.citizenid,
                userId: row.userId != null ? Number(row.userId) : null,
                imageUrl: row.profile_image_url || latestIncidentMugshotUrl,
                profileImageUrl: row.profile_image_url || "",
                latestIncidentMugshotUrl,
                name: getCharacterName(charinfo, row.name),
                money: safeJsonParse(row.money, {}),
                charinfo,
                job: safeJsonParse(row.job, null),
                gang: safeJsonParse(row.gang, null),
                position: safeJsonParse(row.position, null),
                metadata: safeJsonParse(row.metadata, {}),
                inventory: safeJsonParse(row.inventory, null),
                vehicles: vehicleRows[0].map((vehicle) => ({
                    id: Number(vehicle.id),
                    citizenid: vehicle.citizenid,
                    vehicle: vehicle.vehicle_label || "",
                    plate: vehicle.plate || "",
                    notes: vehicle.notes || "",
                    author_username: vehicle.author_username || "",
                    created_at: vehicle.created_at,
                    updated_at: vehicle.updated_at
                })),
                notes: noteRows[0],
                flags: flagRows[0],
                incidents: incidentRows[0],
                lastUpdated: row.last_updated,
                lastLoggedOut: row.last_logged_out,
                canViewSensitiveData
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/:citizenid/notes", async (req, res) => {
    try {
        if (!canAccessSensitiveCharacterData(req.user)) {
            return res.status(403).json({ error: "Only law enforcement can manage citizen notes" })
        }

        const citizenid = String(req.params.citizenid || "").trim()
        const note = String(req.body?.note || "").trim()

        if (!citizenid || !note) {
            return res.status(400).json({ error: "Citizen ID and note are required" })
        }

        await pool.query(
            `
                INSERT INTO mdt_character_notes (citizenid, note, author_id, author_username)
                VALUES (?, ?, ?, ?)
            `,
            [citizenid, note, req.user.id, req.user.username]
        )

        await logAction({
            actor: req.user,
            action: "CHARACTER_NOTE_CREATED",
            targetType: "character",
            targetId: citizenid,
            metadata: { note }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/:citizenid/flags", async (req, res) => {
    try {
        if (!canAccessSensitiveCharacterData(req.user)) {
            return res.status(403).json({ error: "Only law enforcement can manage citizen flags" })
        }

        const citizenid = String(req.params.citizenid || "").trim()
        const flagType = String(req.body?.flagType || "").trim().toLowerCase()
        const title = String(req.body?.title || "").trim()
        const description = String(req.body?.description || "").trim()
        const allowed = new Set(["warning", "bolo", "warrant"])

        if (!citizenid || !allowed.has(flagType) || !title) {
            return res.status(400).json({ error: "Citizen ID, flag type, and title are required" })
        }

        await pool.query(
            `
                INSERT INTO mdt_character_flags (citizenid, flag_type, title, description, author_id, author_username)
                VALUES (?, ?, ?, ?, ?, ?)
            `,
            [citizenid, flagType, title, description || null, req.user.id, req.user.username]
        )

        await logAction({
            actor: req.user,
            action: "CHARACTER_FLAG_CREATED",
            targetType: "character",
            targetId: citizenid,
            metadata: { flagType, title }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/:citizenid/photo", async (req, res) => {
    try {
        if (!canAccessSensitiveCharacterData(req.user)) {
            return res.status(403).json({ error: "Only law enforcement can manage citizen photos" })
        }

        const citizenid = String(req.params.citizenid || "").trim()
        const imageUrl = String(req.body?.imageUrl || "").trim()

        if (!citizenid) {
            return res.status(400).json({ error: "Citizen ID is required" })
        }

        if (imageUrl && !isValidImageUrl(imageUrl)) {
            return res.status(400).json({ error: "Image link must be a valid URL" })
        }

        await pool.query(
            `
                INSERT INTO mdt_character_profiles (citizenid, image_url)
                VALUES (?, ?)
                ON DUPLICATE KEY UPDATE image_url = VALUES(image_url), updated_at = CURRENT_TIMESTAMP
            `,
            [citizenid, imageUrl || null]
        )

        await logAction({
            actor: req.user,
            action: "CHARACTER_PHOTO_UPDATED",
            targetType: "character",
            targetId: citizenid,
            metadata: { imageUrl: imageUrl || null }
        })

        res.json({ success: true, imageUrl: imageUrl || "" })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/:citizenid/vehicles", async (req, res) => {
    try {
        if (!canAccessSensitiveCharacterData(req.user)) {
            return res.status(403).json({ error: "Only law enforcement can manage citizen vehicles" })
        }

        const citizenid = String(req.params.citizenid || "").trim()
        const vehicleLabel = String(req.body?.vehicleLabel || "").trim()
        const plate = String(req.body?.plate || "").trim()
        const notes = String(req.body?.notes || "").trim()

        if (!citizenid || !vehicleLabel) {
            return res.status(400).json({ error: "Citizen ID and vehicle label are required" })
        }

        const [result] = await pool.query(
            `
                INSERT INTO mdt_character_vehicles (citizenid, vehicle_label, plate, notes, author_id, author_username)
                VALUES (?, ?, ?, ?, ?, ?)
            `,
            [citizenid, vehicleLabel, plate || null, notes || null, req.user.id, req.user.username]
        )

        await logAction({
            actor: req.user,
            action: "CHARACTER_VEHICLE_CREATED",
            targetType: "character_vehicle",
            targetId: String(result?.insertId || 0),
            metadata: { citizenid, vehicleLabel, plate: plate || null }
        })

        res.json({ success: true, vehicleId: Number(result?.insertId || 0) })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/:citizenid/notes/:noteId", async (req, res) => {
    try {
        if (!canAccessSensitiveCharacterData(req.user)) {
            return res.status(403).json({ error: "Only law enforcement can manage citizen notes" })
        }

        const citizenid = String(req.params.citizenid || "").trim()
        const noteId = Number.parseInt(req.params.noteId, 10)
        if (!citizenid || !Number.isInteger(noteId) || noteId <= 0) {
            return res.status(400).json({ error: "Citizen ID and note ID are required" })
        }

        await pool.query("DELETE FROM mdt_character_notes WHERE id = ? AND citizenid = ?", [noteId, citizenid])
        await logAction({
            actor: req.user,
            action: "CHARACTER_NOTE_DELETED",
            targetType: "character_note",
            targetId: String(noteId),
            metadata: { citizenid }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/:citizenid/flags/:flagId", async (req, res) => {
    try {
        if (!canAccessSensitiveCharacterData(req.user)) {
            return res.status(403).json({ error: "Only law enforcement can manage citizen flags" })
        }

        const citizenid = String(req.params.citizenid || "").trim()
        const flagId = Number.parseInt(req.params.flagId, 10)
        if (!citizenid || !Number.isInteger(flagId) || flagId <= 0) {
            return res.status(400).json({ error: "Citizen ID and flag ID are required" })
        }

        await pool.query("DELETE FROM mdt_character_flags WHERE id = ? AND citizenid = ?", [flagId, citizenid])
        await logAction({
            actor: req.user,
            action: "CHARACTER_FLAG_DELETED",
            targetType: "character_flag",
            targetId: String(flagId),
            metadata: { citizenid }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/:citizenid/vehicles/:vehicleId", async (req, res) => {
    try {
        if (!canAccessSensitiveCharacterData(req.user)) {
            return res.status(403).json({ error: "Only law enforcement can manage citizen vehicles" })
        }

        const citizenid = String(req.params.citizenid || "").trim()
        const vehicleId = Number.parseInt(req.params.vehicleId, 10)
        if (!citizenid || !Number.isInteger(vehicleId) || vehicleId <= 0) {
            return res.status(400).json({ error: "Citizen ID and vehicle ID are required" })
        }

        await pool.query("DELETE FROM mdt_character_vehicles WHERE id = ? AND citizenid = ?", [vehicleId, citizenid])
        await logAction({
            actor: req.user,
            action: "CHARACTER_VEHICLE_DELETED",
            targetType: "character_vehicle",
            targetId: String(vehicleId),
            metadata: { citizenid }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
