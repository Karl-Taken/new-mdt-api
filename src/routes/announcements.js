const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const requirePermission = require("../middleware/requirePermission")
const logAction = require("../utils/auditLogger")

const router = express.Router()
router.use(auth)
router.use(requirePermission("announcements.view"))

function canAccessTab(user, tabId, permission = "view") {
    if (user?.role === "superadmin") {
        return true
    }

    const access = (user?.tabs || []).find((tab) => Number(tab.id) === Number(tabId))?.access || null
    if (!access) {
        return false
    }

    if (permission === "manage") {
        return Boolean(access.canManage)
    }

    if (permission === "edit") {
        return Boolean(access.canEdit || access.canManage)
    }

    return Boolean(access.canView || access.canEdit || access.canManage)
}

router.get("/", async (req, res) => {
    try {
        const tabId = Number.parseInt(req.query?.tabId, 10)
        if (Number.isInteger(tabId) && tabId > 0 && !canAccessTab(req.user, tabId, "view")) {
            return res.status(403).json({ error: "You do not have access to this announcements tab" })
        }

        const scopeClause = Number.isInteger(tabId) && tabId > 0 ? "tab_id = ?" : "tab_id IS NULL"
        const scopeParams = Number.isInteger(tabId) && tabId > 0 ? [tabId] : []

        const [rows] = await pool.query(
            `
                SELECT id, tab_id, title, body, priority, author_username, is_active, created_at, updated_at
                FROM mdt_announcements
                WHERE is_active = 1
                    AND ${scopeClause}
                ORDER BY created_at DESC
            `,
            scopeParams
        )

        res.json({ announcements: rows, scopedToTabId: Number.isInteger(tabId) && tabId > 0 ? tabId : null })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/", async (req, res) => {
    try {
        const title = String(req.body?.title || "").trim()
        const body = String(req.body?.body || "").trim()
        const priority = String(req.body?.priority || "normal").trim().toLowerCase()
        const tabId = req.body?.tabId ? Number(req.body.tabId) : null

        if (!title || !body) {
            return res.status(400).json({ error: "Title and body are required" })
        }

        if (tabId) {
            if (!canAccessTab(req.user, tabId, "edit")) {
                return res.status(403).json({ error: "You do not have edit access to this announcements tab" })
            }
        } else if (!["admin", "superadmin"].includes(String(req.user?.role || ""))) {
            return res.status(403).json({ error: "You do not have permission to create global announcements" })
        }

        await pool.query(
            `
                INSERT INTO mdt_announcements (tab_id, title, body, priority, author_id, author_username)
                VALUES (?, ?, ?, ?, ?, ?)
            `,
            [tabId, title, body, priority || "normal", req.user.id, req.user.username]
        )

        await logAction({
            actor: req.user,
            action: "ANNOUNCEMENT_CREATED",
            targetType: "announcement",
            targetId: title
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/:announcementId", async (req, res) => {
    try {
        const announcementId = Number.parseInt(req.params.announcementId, 10)
        if (!Number.isInteger(announcementId) || announcementId <= 0) {
            return res.status(400).json({ error: "Invalid announcement id" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, tab_id, title
                FROM mdt_announcements
                WHERE id = ?
                LIMIT 1
            `,
            [announcementId]
        )

        const announcement = rows?.[0]
        if (!announcement) {
            return res.status(404).json({ error: "Announcement not found" })
        }

        if (announcement.tab_id) {
            if (!canAccessTab(req.user, announcement.tab_id, "edit")) {
                return res.status(403).json({ error: "You do not have edit access to this announcements tab" })
            }
        } else if (!["admin", "superadmin"].includes(String(req.user?.role || ""))) {
            return res.status(403).json({ error: "You do not have permission to delete global announcements" })
        }

        await pool.query(
            `
                UPDATE mdt_announcements
                SET is_active = 0
                WHERE id = ?
            `,
            [announcementId]
        )

        await logAction({
            actor: req.user,
            action: "ANNOUNCEMENT_DELETED",
            targetType: "announcement",
            targetId: announcement.id,
            meta: { title: announcement.title, tabId: announcement.tab_id || null }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
