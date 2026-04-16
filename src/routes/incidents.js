const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const logAction = require("../utils/auditLogger")

const router = express.Router()
router.use(auth)

function getTabAccess(user, tabId) {
    return (user?.tabs || []).find((tab) => Number(tab.id) === Number(tabId))?.access || null
}

function canAccessTab(user, tabId, permission) {
    if (user?.role === "superadmin") {
        return true
    }

    const access = getTabAccess(user, tabId)
    if (!access) {
        return false
    }

    if (permission === "manage") {
        return !!access.canManage
    }
    if (permission === "edit") {
        return !!(access.canEdit || access.canManage)
    }
    return !!(access.canView || access.canEdit || access.canManage)
}

function buildIncidentNumber() {
    return `INC-${Date.now()}`
}

function normalizeDraftKey(value) {
    return String(value || "").trim().slice(0, 128)
}

function parseDraftPayload(value) {
    if (!value) {
        return null
    }

    try {
        return JSON.parse(value)
    } catch (_error) {
        return null
    }
}

function normalizeEditorKey(value) {
    return String(value || "").trim().slice(0, 128)
}

function getPresenceColor(userId) {
    const colors = ["#38bdf8", "#22c55e", "#f97316", "#f43f5e", "#a78bfa", "#facc15", "#2dd4bf"]
    const index = Math.abs(Number(userId || 0)) % colors.length
    return colors[index]
}

function parseCursorPayload(value) {
    if (!value) {
        return null
    }

    try {
        const cursor = JSON.parse(value)
        if (!cursor || typeof cursor !== "object") {
            return null
        }
        return cursor
    } catch (_error) {
        return null
    }
}

router.get("/drafts/:draftKey", async (req, res) => {
    try {
        const draftKey = normalizeDraftKey(req.params.draftKey)
        if (!draftKey) {
            return res.status(400).json({ error: "Draft key is required" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, draft_key, incident_id, payload, revision, last_editor_id, last_editor_username, created_at, updated_at
                FROM mdt_incident_drafts
                WHERE draft_key = ?
                LIMIT 1
            `,
            [draftKey]
        )

        if (!rows.length) {
            return res.json({ draft: null })
        }

        const draft = rows[0]
        res.json({
            draft: {
                id: draft.id,
                draftKey: draft.draft_key,
                incidentId: draft.incident_id,
                payload: parseDraftPayload(draft.payload),
                revision: Number(draft.revision || 0),
                createdAt: draft.created_at,
                updatedAt: draft.updated_at,
                lastEditor: {
                    id: draft.last_editor_id,
                    username: draft.last_editor_username
                }
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/drafts/:draftKey", async (req, res) => {
    try {
        const draftKey = normalizeDraftKey(req.params.draftKey)
        if (!draftKey) {
            return res.status(400).json({ error: "Draft key is required" })
        }

        const payload = req.body?.payload
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
            return res.status(400).json({ error: "Draft payload is required" })
        }

        const incidentId = req.body?.incidentId ? Number(req.body.incidentId) : null
        const serializedPayload = JSON.stringify(payload)

        await pool.query(
            `
                INSERT INTO mdt_incident_drafts (draft_key, incident_id, payload, revision, last_editor_id, last_editor_username)
                VALUES (?, ?, ?, 1, ?, ?)
                ON DUPLICATE KEY UPDATE
                    incident_id = VALUES(incident_id),
                    payload = VALUES(payload),
                    revision = revision + 1,
                    last_editor_id = VALUES(last_editor_id),
                    last_editor_username = VALUES(last_editor_username),
                    updated_at = CURRENT_TIMESTAMP
            `,
            [draftKey, incidentId, serializedPayload, req.user.id, req.user.username]
        )

        const [rows] = await pool.query(
            `
                SELECT id, draft_key, incident_id, revision, last_editor_id, last_editor_username, created_at, updated_at
                FROM mdt_incident_drafts
                WHERE draft_key = ?
                LIMIT 1
            `,
            [draftKey]
        )

        const draft = rows[0]
        res.json({
            success: true,
            draft: {
                id: draft.id,
                draftKey: draft.draft_key,
                incidentId: draft.incident_id,
                revision: Number(draft.revision || 0),
                createdAt: draft.created_at,
                updatedAt: draft.updated_at,
                lastEditor: {
                    id: draft.last_editor_id,
                    username: draft.last_editor_username
                }
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/drafts/:draftKey", async (req, res) => {
    try {
        const draftKey = normalizeDraftKey(req.params.draftKey)
        if (!draftKey) {
            return res.status(400).json({ error: "Draft key is required" })
        }

        await pool.query("DELETE FROM mdt_incident_drafts WHERE draft_key = ?", [draftKey])
        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/drafts/:draftKey/presence", async (req, res) => {
    try {
        const draftKey = normalizeDraftKey(req.params.draftKey)
        const editorKey = normalizeEditorKey(req.query?.editorKey)
        if (!draftKey || !editorKey) {
            return res.status(400).json({ error: "Draft key and editor key are required" })
        }

        const [rows] = await pool.query(
            `
                SELECT user_id, username, cursor_json, color, updated_at
                FROM mdt_incident_draft_presence
                WHERE draft_key = ?
                    AND editor_key = ?
                    AND user_id <> ?
                    AND updated_at >= (CURRENT_TIMESTAMP - INTERVAL 20 SECOND)
                ORDER BY updated_at DESC
            `,
            [draftKey, editorKey, req.user.id]
        )

        res.json({
            presence: rows.map((row) => ({
                userId: row.user_id,
                username: row.username,
                cursor: parseCursorPayload(row.cursor_json),
                color: row.color || getPresenceColor(row.user_id),
                updatedAt: row.updated_at
            }))
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/drafts/:draftKey/presence", async (req, res) => {
    try {
        const draftKey = normalizeDraftKey(req.params.draftKey)
        const editorKey = normalizeEditorKey(req.body?.editorKey)
        const cursor = req.body?.cursor && typeof req.body.cursor === "object" ? req.body.cursor : null
        if (!draftKey || !editorKey) {
            return res.status(400).json({ error: "Draft key and editor key are required" })
        }

        const serializedCursor = cursor ? JSON.stringify(cursor).slice(0, 2000) : null
        const color = getPresenceColor(req.user.id)

        await pool.query(
            `
                INSERT INTO mdt_incident_draft_presence (draft_key, editor_key, user_id, username, cursor_json, color)
                VALUES (?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    username = VALUES(username),
                    cursor_json = VALUES(cursor_json),
                    color = VALUES(color),
                    updated_at = CURRENT_TIMESTAMP
            `,
            [draftKey, editorKey, req.user.id, req.user.username, serializedCursor, color]
        )

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/drafts/:draftKey/presence", async (req, res) => {
    try {
        const draftKey = normalizeDraftKey(req.params.draftKey)
        const editorKey = normalizeEditorKey(req.query?.editorKey)
        if (!draftKey || !editorKey) {
            return res.status(400).json({ error: "Draft key and editor key are required" })
        }

        await pool.query(
            "DELETE FROM mdt_incident_draft_presence WHERE draft_key = ? AND editor_key = ? AND user_id = ?",
            [draftKey, editorKey, req.user.id]
        )
        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/", async (req, res) => {
    try {
        const tabId = Number.parseInt(req.query?.tabId, 10)
        if (Number.isInteger(tabId) && tabId > 0 && !canAccessTab(req.user, tabId, "view")) {
            return res.status(403).json({ error: "You do not have access to this incident tab" })
        }

        const scopeClause = Number.isInteger(tabId) && tabId > 0 ? "incidents.tab_id = ?" : "incidents.tab_id IS NULL"
        const scopeParams = Number.isInteger(tabId) && tabId > 0 ? [tabId] : []

        const [rows] = await pool.query(
            `
                SELECT
                    incidents.id,
                    incidents.tab_id,
                    incidents.incident_number,
                    incidents.title,
                    incidents.summary,
                    incidents.location,
                    incidents.status,
                    incidents.occurred_at,
                    incidents.author_username,
                    incidents.created_at,
                    reports.title AS primary_report_title,
                    reports.report_text AS primary_report_text
                FROM mdt_incidents incidents
                LEFT JOIN mdt_incident_reports reports
                    ON reports.incident_id = incidents.id
                    AND reports.display_order = (
                        SELECT MIN(inner_reports.display_order)
                        FROM mdt_incident_reports inner_reports
                        WHERE inner_reports.incident_id = incidents.id
                    )
                WHERE ${scopeClause}
                ORDER BY COALESCE(incidents.occurred_at, incidents.created_at) DESC
                LIMIT 100
            `,
            scopeParams
        )

        res.json({ incidents: rows, scopedToTabId: Number.isInteger(tabId) && tabId > 0 ? tabId : null })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/:incidentId", async (req, res) => {
    try {
        const incidentId = Number.parseInt(req.params.incidentId, 10)
        if (!Number.isInteger(incidentId) || incidentId <= 0) {
            return res.status(400).json({ error: "Incident ID is required" })
        }

        const [incidentRows] = await pool.query(
            `
                SELECT id, tab_id, incident_number, title, summary, narrative, location, status, occurred_at, author_username, created_at, updated_at
                FROM mdt_incidents
                WHERE id = ?
                LIMIT 1
            `,
            [incidentId]
        )

        if (!incidentRows.length) {
            return res.status(404).json({ error: "Incident not found" })
        }

        const incident = incidentRows[0]
        if (incident.tab_id && !canAccessTab(req.user, incident.tab_id, "view")) {
            return res.status(403).json({ error: "You do not have access to this incident" })
        }

        const [peopleRows, officerRows, reportRows, chargeRows, evidenceRows] = await Promise.all([
            pool.query(
                `
                    SELECT people.id, people.citizenid, people.role, people.notes, profile.image_url AS image_url
                    FROM mdt_incident_people people
                    LEFT JOIN mdt_character_profiles profile ON profile.citizenid = people.citizenid
                    WHERE people.incident_id = ?
                    ORDER BY people.id ASC
                `,
                [incidentId]
            ),
            pool.query(
                `
                    SELECT id, officer_name, callsign, role
                    FROM mdt_incident_officers
                    WHERE incident_id = ?
                    ORDER BY id ASC
                `,
                [incidentId]
            ),
            pool.query(
                `
                    SELECT id, title, report_type, report_html, report_text, display_order, author_username, created_at, updated_at
                    FROM mdt_incident_reports
                    WHERE incident_id = ?
                    ORDER BY display_order ASC, id ASC
                `,
                [incidentId]
            ),
            pool.query(
                `
                    SELECT id, citizenid, charge_id, charge_title, count, fine, jail_time
                    FROM mdt_incident_charges
                    WHERE incident_id = ?
                    ORDER BY id ASC
                `,
                [incidentId]
            ),
            pool.query(
                `
                    SELECT id, evidence_tag, badge_number, badge_color, evidence_type, title, description, image_url
                    FROM mdt_evidence
                    WHERE incident_id = ?
                    ORDER BY id DESC
                `,
                [incidentId]
            )
        ])

        res.json({
            incident: {
                ...incident,
                people: peopleRows[0],
                officers: officerRows[0],
                reports: reportRows[0],
                charges: chargeRows[0],
                evidence: evidenceRows[0]
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/", async (req, res) => {
    try {
        const draftKey = normalizeDraftKey(req.body?.draftKey)
        const tabId = req.body?.tabId ? Number(req.body.tabId) : null
        if (tabId && !canAccessTab(req.user, tabId, "edit")) {
            return res.status(403).json({ error: "You do not have edit access to this incident tab" })
        }

        const reports = Array.isArray(req.body?.reports) ? req.body.reports : []
        const normalizedReports = reports
            .map((report, index) => ({
                title: String(report?.title || "").trim(),
                reportType: String(report?.reportType || "").trim() || "investigation_report",
                reportHtml: String(report?.reportHtml || "").trim(),
                reportText: String(report?.reportText || "").trim(),
                displayOrder: index + 1
            }))
            .filter((report) => report.title || report.reportHtml || report.reportText)
        const title = String(req.body?.title || "").trim() || normalizedReports[0]?.title || "Untitled Incident"

        const fallbackSummary = normalizedReports[0]?.reportHtml || String(req.body?.summary || "").trim() || null
        const fallbackNarrative = String(req.body?.narrative || "").trim() || normalizedReports[0]?.reportText || null

        const incidentNumber = buildIncidentNumber()
        await pool.query(
            `
                INSERT INTO mdt_incidents (incident_number, title, summary, narrative, location, status, tab_id, occurred_at, author_id, author_username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
                incidentNumber,
                title,
                fallbackSummary,
                fallbackNarrative,
                String(req.body?.location || "").trim() || null,
                String(req.body?.status || "open").trim() || "open",
                tabId,
                req.body?.occurredAt || null,
                req.user.id,
                req.user.username
            ]
        )

        const [createdRows] = await pool.query(
            "SELECT id FROM mdt_incidents WHERE incident_number = ? LIMIT 1",
            [incidentNumber]
        )
        const incidentId = Number(createdRows[0]?.id || 0)

        const people = Array.isArray(req.body?.people) ? req.body.people : []
        const officers = Array.isArray(req.body?.officers) ? req.body.officers : []
        const charges = Array.isArray(req.body?.charges) ? req.body.charges : []

        for (const report of normalizedReports) {
            await pool.query(
                `
                    INSERT INTO mdt_incident_reports (incident_id, title, report_type, report_html, report_text, display_order, author_id, author_username)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                    incidentId,
                    report.title || "Untitled Report",
                    report.reportType,
                    report.reportHtml || null,
                    report.reportText || null,
                    report.displayOrder,
                    req.user.id,
                    req.user.username
                ]
            )
        }

        for (const person of people) {
            const citizenid = String(person?.citizenid || "").trim()
            if (!citizenid) {
                continue
            }

            await pool.query(
                `
                    INSERT INTO mdt_incident_people (incident_id, citizenid, role, notes)
                    VALUES (?, ?, ?, ?)
                `,
                [
                    incidentId,
                    citizenid,
                    String(person?.role || "subject").trim() || "subject",
                    String(person?.notes || "").trim() || null
                ]
            )
        }

        for (const officer of officers) {
            const officerName = String(officer?.officerName || "").trim()
            if (!officerName) {
                continue
            }

            await pool.query(
                `
                    INSERT INTO mdt_incident_officers (incident_id, officer_name, callsign, role)
                    VALUES (?, ?, ?, ?)
                `,
                [
                    incidentId,
                    officerName,
                    String(officer?.callsign || "").trim() || null,
                    String(officer?.role || "").trim() || null
                ]
            )
        }

        for (const charge of charges) {
            const citizenid = String(charge?.citizenid || "").trim()
            const chargeTitle = String(charge?.chargeTitle || "").trim()

            if (!citizenid || !chargeTitle) {
                continue
            }

            await pool.query(
                `
                    INSERT INTO mdt_incident_charges (incident_id, citizenid, charge_id, charge_title, count, fine, jail_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `,
                [
                    incidentId,
                    citizenid,
                    charge?.chargeId ? Number(charge.chargeId) : null,
                    chargeTitle,
                    Number(charge?.count || 1),
                    Number(charge?.fine || 0),
                    Number(charge?.jailTime || 0)
                ]
            )
        }

        await logAction({
            actor: req.user,
            action: "INCIDENT_CREATED",
            targetType: "incident",
            targetId: String(incidentId),
            metadata: { incidentNumber, title }
        })

        if (draftKey) {
            await pool.query("DELETE FROM mdt_incident_drafts WHERE draft_key = ?", [draftKey])
        }

        res.json({
            success: true,
            incidentId,
            incidentNumber
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/:incidentId", async (req, res) => {
    try {
        const incidentId = Number.parseInt(req.params.incidentId, 10)
        const draftKey = normalizeDraftKey(req.body?.draftKey)
        const tabId = req.body?.tabId ? Number(req.body.tabId) : null
        if (!Number.isInteger(incidentId) || incidentId <= 0) {
            return res.status(400).json({ error: "Incident ID is required" })
        }

        const [existingRows] = await pool.query(
            `
                SELECT id, tab_id
                FROM mdt_incidents
                WHERE id = ?
                LIMIT 1
            `,
            [incidentId]
        )

        if (!existingRows.length) {
            return res.status(404).json({ error: "Incident not found" })
        }

        const existingIncident = existingRows[0]
        if (existingIncident.tab_id && !canAccessTab(req.user, existingIncident.tab_id, "edit")) {
            return res.status(403).json({ error: "You do not have edit access to this incident" })
        }
        if (tabId && !canAccessTab(req.user, tabId, "edit")) {
            return res.status(403).json({ error: "You do not have edit access to the selected incident tab" })
        }

        const reports = Array.isArray(req.body?.reports) ? req.body.reports : []
        const normalizedReports = reports
            .map((report, index) => ({
                title: String(report?.title || "").trim(),
                reportType: String(report?.reportType || "").trim() || "investigation_report",
                reportHtml: String(report?.reportHtml || "").trim(),
                reportText: String(report?.reportText || "").trim(),
                displayOrder: index + 1
            }))
            .filter((report) => report.title || report.reportHtml || report.reportText)
        const title = String(req.body?.title || "").trim() || normalizedReports[0]?.title || "Untitled Incident"

        const fallbackSummary = normalizedReports[0]?.reportHtml || String(req.body?.summary || "").trim() || null
        const fallbackNarrative = String(req.body?.narrative || "").trim() || normalizedReports[0]?.reportText || null

        await pool.query(
            `
                UPDATE mdt_incidents
                SET title = ?, summary = ?, narrative = ?, location = ?, status = ?, tab_id = ?, occurred_at = ?, updated_at = NOW()
                WHERE id = ?
            `,
            [
                title,
                fallbackSummary,
                fallbackNarrative,
                String(req.body?.location || "").trim() || null,
                String(req.body?.status || "open").trim() || "open",
                tabId,
                req.body?.occurredAt || null,
                incidentId
            ]
        )

        const people = Array.isArray(req.body?.people) ? req.body.people : []
        const officers = Array.isArray(req.body?.officers) ? req.body.officers : []
        const charges = Array.isArray(req.body?.charges) ? req.body.charges : []

        await pool.query("DELETE FROM mdt_incident_people WHERE incident_id = ?", [incidentId])
        await pool.query("DELETE FROM mdt_incident_officers WHERE incident_id = ?", [incidentId])
        await pool.query("DELETE FROM mdt_incident_reports WHERE incident_id = ?", [incidentId])
        await pool.query("DELETE FROM mdt_incident_charges WHERE incident_id = ?", [incidentId])

        for (const report of normalizedReports) {
            await pool.query(
                `
                    INSERT INTO mdt_incident_reports (incident_id, title, report_type, report_html, report_text, display_order, author_id, author_username)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                    incidentId,
                    report.title || "Untitled Report",
                    report.reportType,
                    report.reportHtml || null,
                    report.reportText || null,
                    report.displayOrder,
                    req.user.id,
                    req.user.username
                ]
            )
        }

        for (const person of people) {
            const citizenid = String(person?.citizenid || "").trim()
            if (!citizenid) {
                continue
            }

            await pool.query(
                `
                    INSERT INTO mdt_incident_people (incident_id, citizenid, role, notes)
                    VALUES (?, ?, ?, ?)
                `,
                [
                    incidentId,
                    citizenid,
                    String(person?.role || "subject").trim() || "subject",
                    String(person?.notes || "").trim() || null
                ]
            )
        }

        for (const officer of officers) {
            const officerName = String(officer?.officerName || "").trim()
            if (!officerName) {
                continue
            }

            await pool.query(
                `
                    INSERT INTO mdt_incident_officers (incident_id, officer_name, callsign, role)
                    VALUES (?, ?, ?, ?)
                `,
                [
                    incidentId,
                    officerName,
                    String(officer?.callsign || "").trim() || null,
                    String(officer?.role || "").trim() || null
                ]
            )
        }

        for (const charge of charges) {
            const citizenid = String(charge?.citizenid || "").trim()
            const chargeTitle = String(charge?.chargeTitle || "").trim()

            if (!citizenid || !chargeTitle) {
                continue
            }

            await pool.query(
                `
                    INSERT INTO mdt_incident_charges (incident_id, citizenid, charge_id, charge_title, count, fine, jail_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `,
                [
                    incidentId,
                    citizenid,
                    charge?.chargeId ? Number(charge.chargeId) : null,
                    chargeTitle,
                    Number(charge?.count || 1),
                    Number(charge?.fine || 0),
                    Number(charge?.jailTime || 0)
                ]
            )
        }

        await logAction({
            actor: req.user,
            action: "INCIDENT_UPDATED",
            targetType: "incident",
            targetId: String(incidentId),
            metadata: { title }
        })

        if (draftKey) {
            await pool.query("DELETE FROM mdt_incident_drafts WHERE draft_key = ?", [draftKey])
        }

        res.json({ success: true, incidentId })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
