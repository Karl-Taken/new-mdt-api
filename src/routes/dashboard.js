const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const requirePermission = require("../middleware/requirePermission")

const router = express.Router()
router.use(auth)
router.use(requirePermission("dashboard.view"))

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
        const hasScopedTab = Number.isInteger(tabId) && tabId > 0
        if (hasScopedTab && !canAccessTab(req.user, tabId, "view")) {
            return res.status(403).json({ error: "You do not have access to this dashboard tab" })
        }

        const incidentCountQuery = hasScopedTab
            ? "SELECT COUNT(*) AS total FROM mdt_incidents WHERE tab_id = ?"
            : "SELECT COUNT(*) AS total FROM mdt_incidents"
        const evidenceCountQuery = hasScopedTab
            ? `
                SELECT COUNT(*) AS total
                FROM mdt_evidence evidence
                INNER JOIN mdt_incidents incidents
                    ON incidents.id = evidence.incident_id
                WHERE incidents.tab_id = ?
            `
            : "SELECT COUNT(*) AS total FROM mdt_evidence"
        const announcementCountQuery = hasScopedTab
            ? "SELECT COUNT(*) AS total FROM mdt_announcements WHERE is_active = 1 AND tab_id = ?"
            : "SELECT COUNT(*) AS total FROM mdt_announcements WHERE is_active = 1"
        const recentIncidentsQuery = hasScopedTab
            ? `
                SELECT id, incident_number, title, status, occurred_at, created_at
                FROM mdt_incidents
                WHERE tab_id = ?
                ORDER BY COALESCE(occurred_at, created_at) DESC
                LIMIT 5
            `
            : `
                SELECT id, incident_number, title, status, occurred_at, created_at
                FROM mdt_incidents
                ORDER BY COALESCE(occurred_at, created_at) DESC
                LIMIT 5
            `

        const [
            [characterRows],
            [vehicleRows],
            [incidentRows],
            [evidenceRows],
            [announcementRows]
        ] = await Promise.all([
            pool.query("SELECT COUNT(*) AS total FROM players"),
            pool.query("SELECT COUNT(*) AS total FROM player_vehicles"),
            pool.query(incidentCountQuery, hasScopedTab ? [tabId] : []),
            pool.query(evidenceCountQuery, hasScopedTab ? [tabId] : []),
            pool.query(announcementCountQuery, hasScopedTab ? [tabId] : [])
        ])

        const [recentIncidents] = await pool.query(
            recentIncidentsQuery,
            hasScopedTab ? [tabId] : []
        )

        res.json({
            stats: {
                characters: Number(characterRows[0]?.total || 0),
                vehicles: Number(vehicleRows[0]?.total || 0),
                incidents: Number(incidentRows[0]?.total || 0),
                evidence: Number(evidenceRows[0]?.total || 0),
                announcements: Number(announcementRows[0]?.total || 0)
            },
            recentIncidents
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
