const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const requirePermission = require("../middleware/requirePermission")
const logAction = require("../utils/auditLogger")

const router = express.Router()
router.use(auth)
router.use(requirePermission("roster.view"))
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

function normalizeGroupSlug(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
}

async function getRosterTab(tabId) {
    const [rows] = await pool.query(
        `
            SELECT id, group_id, path, roster_default_role, roster_default_group_id
            FROM mdt_tabs
            WHERE id = ?
            LIMIT 1
        `,
        [tabId]
    )
    return rows[0] || null
}

async function getGroupIdFromTabPath(tab) {
    const pathSlug = String(tab?.path || "").match(/\/groups\/([^/]+)/i)?.[1]
    if (!pathSlug) {
        return null
    }

    const normalizedPathSlug = normalizeGroupSlug(pathSlug)
    const [rows] = await pool.query(
        `
            SELECT id, name
            FROM mdt_groups
        `
    )
    const matchedGroup = rows.find((group) => normalizeGroupSlug(group.name) === normalizedPathSlug)
    return matchedGroup?.id || null
}

async function resolveRosterGroupId(tab) {
    const pathGroupId = await getGroupIdFromTabPath(tab)
    if (pathGroupId) {
        return pathGroupId
    }
    return tab?.group_id || null
}

async function resolveRequestedRosterGroupId(tab, candidateGroupId) {
    const parsedGroupId = Number.parseInt(candidateGroupId, 10)
    if (Number.isInteger(parsedGroupId) && parsedGroupId > 0) {
        return parsedGroupId
    }

    const resolvedTabGroupId = await resolveRosterGroupId(tab)
    if (resolvedTabGroupId) {
        return resolvedTabGroupId
    }

    const defaultGroupId = Number(tab?.roster_default_group_id || 0)
    return defaultGroupId > 0 ? defaultGroupId : null
}

async function getRosterRanks(groupId) {
    if (!groupId) {
        return []
    }

    const [rows] = await pool.query(
        `
            SELECT id, group_id, name, sort_order
            FROM mdt_group_ranks
            WHERE group_id = ?
            ORDER BY sort_order ASC, name ASC
        `,
        [groupId]
    )

    return rows
}

async function getAllAccessGroups() {
    const [rows] = await pool.query(
        `
            SELECT id, name
            FROM mdt_groups
            ORDER BY name ASC
        `
    )

    return rows.map((group) => ({
        id: Number(group.id),
        name: String(group.name || "")
    }))
}

async function getDefaultRankForGroup(groupId) {
    if (!groupId) {
        return null
    }

    const [rows] = await pool.query(
        `
            SELECT id, group_id, name
            FROM mdt_group_ranks
            WHERE group_id = ?
            ORDER BY sort_order ASC, id ASC
            LIMIT 1
        `,
        [groupId]
    )

    return rows[0] || null
}

async function syncUserMembershipForGroup({ userId, groupId, rankId }) {
    if (!userId || !groupId || !rankId) {
        return
    }

    const [rankRows] = await pool.query(
        `
            SELECT id, group_id
            FROM mdt_group_ranks
            WHERE id = ?
            LIMIT 1
        `,
        [rankId]
    )

    const rank = rankRows[0]
    if (!rank || Number(rank.group_id) !== Number(groupId)) {
        return
    }

    await pool.query(
        `
            INSERT INTO mdt_user_group_memberships (user_id, group_id, rank_id, is_active)
            VALUES (?, ?, ?, 1)
            ON DUPLICATE KEY UPDATE rank_id = VALUES(rank_id), is_active = 1
        `,
        [userId, groupId, rankId]
    )
}

async function applyRosterUserAccess({ tab, rosterGroupId, userId, rankId }) {
    if (!userId) {
        return
    }

    if (userId && tab?.roster_default_group_id) {
        const defaultRank = await getDefaultRankForGroup(Number(tab.roster_default_group_id))
        if (defaultRank) {
            await syncUserMembershipForGroup({
                userId,
                groupId: Number(defaultRank.group_id),
                rankId: Number(defaultRank.id)
            })
        }
    }

    await syncUserMembershipForGroup({ userId, groupId: rosterGroupId, rankId })
}

router.get("/", async (req, res) => {
    try {
        const tabId = Number.parseInt(req.query?.tabId, 10)
        if (Number.isInteger(tabId) && tabId > 0) {
            if (!canAccessTab(req.user, tabId, "view")) {
                return res.status(403).json({ error: "You do not have access to this roster tab" })
            }

            const tab = await getRosterTab(tabId)
            const rosterGroupId = await resolveRequestedRosterGroupId(tab, req.query?.groupId)
            const [rows, ranks, groups] = await Promise.all([
                pool.query(
                `
                    SELECT entries.id, entries.tab_id, entries.user_id, entries.citizenid, entries.rank_id, entries.display_name,
                           entries.rank_label, entries.unit_label, entries.notes, entries.is_active, entries.created_at, entries.updated_at,
                           users.username,
                           profile.image_url AS image_url
                    FROM mdt_roster_entries entries
                    LEFT JOIN mdt_users users ON users.id = entries.user_id
                    LEFT JOIN mdt_character_profiles profile ON profile.citizenid = entries.citizenid
                    WHERE entries.tab_id = ?
                        AND entries.is_active = 1
                    ORDER BY entries.rank_label ASC, entries.display_name ASC
                `,
                [tabId]
                ),
                getRosterRanks(rosterGroupId),
                getAllAccessGroups()
            ])

            return res.json({
                roster: rows[0],
                scopedToTabId: tabId,
                rosterGroupId,
                ranks,
                groups,
                rosterDefaultGroupId: tab?.roster_default_group_id ? Number(tab.roster_default_group_id) : null
            })
        }

        const [rows] = await pool.query(
            `
                SELECT id, username, role, is_active, last_login_at, created_at
                FROM mdt_users
                ORDER BY role ASC, username ASC
            `
        )

        res.json({ roster: rows, scopedToTabId: null })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/", async (req, res) => {
    try {
        const tabId = Number.parseInt(req.body?.tabId, 10)
        const displayName = String(req.body?.displayName || "").trim()

        if (!Number.isInteger(tabId) || tabId <= 0) {
            return res.status(400).json({ error: "Tab ID is required" })
        }

        if (!canAccessTab(req.user, tabId, "edit")) {
            return res.status(403).json({ error: "You do not have edit access to this roster tab" })
        }

        if (!displayName) {
            return res.status(400).json({ error: "Display name is required" })
        }

        const tab = await getRosterTab(tabId)
        const rosterGroupId = tab ? await resolveRequestedRosterGroupId(tab, req.body?.groupId) : null
        const rankId = req.body?.rankId ? Number.parseInt(req.body.rankId, 10) : null
        const userId = req.body?.userId ? Number(req.body.userId) : null
        const rankLabel = String(req.body?.rankLabel || "").trim()
        const resolvedRankLabel = rankLabel || ""

        const [result] = await pool.query(
            `
                INSERT INTO mdt_roster_entries (tab_id, user_id, citizenid, rank_id, display_name, rank_label, unit_label, notes, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            `,
            [
                tabId,
                userId,
                String(req.body?.citizenid || "").trim() || null,
                rankId,
                displayName,
                resolvedRankLabel || null,
                String(req.body?.unitLabel || "").trim() || null,
                String(req.body?.notes || "").trim() || null
            ]
        )

        await applyRosterUserAccess({ tab, rosterGroupId, userId, rankId })

        await logAction({
            actor: req.user,
            action: "ROSTER_ENTRY_CREATED",
            targetType: "roster_entry",
            targetId: String(result?.insertId || 0),
            metadata: { tabId, displayName }
        })

        res.json({ success: true, rosterEntryId: Number(result?.insertId || 0) })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/:entryId", async (req, res) => {
    try {
        const entryId = Number.parseInt(req.params.entryId, 10)
        if (!Number.isInteger(entryId) || entryId <= 0) {
            return res.status(400).json({ error: "Roster entry ID is required" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, tab_id
                FROM mdt_roster_entries
                WHERE id = ?
                LIMIT 1
            `,
            [entryId]
        )

        if (!rows.length) {
            return res.status(404).json({ error: "Roster entry not found" })
        }

        const entry = rows[0]
        if (!canAccessTab(req.user, entry.tab_id, "edit")) {
            return res.status(403).json({ error: "You do not have edit access to this roster tab" })
        }

        const displayName = String(req.body?.displayName || "").trim()
        if (!displayName) {
            return res.status(400).json({ error: "Display name is required" })
        }

        const tab = await getRosterTab(entry.tab_id)
        const rosterGroupId = tab ? await resolveRequestedRosterGroupId(tab, req.body?.groupId) : null
        const rankId = req.body?.rankId ? Number.parseInt(req.body.rankId, 10) : null
        const userId = req.body?.userId ? Number(req.body.userId) : null

        await pool.query(
            `
                UPDATE mdt_roster_entries
                SET user_id = ?,
                    citizenid = ?,
                    rank_id = ?,
                    display_name = ?,
                    rank_label = ?,
                    unit_label = ?,
                    notes = ?,
                    is_active = 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `,
            [
                userId,
                String(req.body?.citizenid || "").trim() || null,
                rankId,
                displayName,
                String(req.body?.rankLabel || "").trim() || null,
                String(req.body?.unitLabel || "").trim() || null,
                String(req.body?.notes || "").trim() || null,
                entryId
            ]
        )

        await applyRosterUserAccess({ tab, rosterGroupId, userId, rankId })

        await logAction({
            actor: req.user,
            action: "ROSTER_ENTRY_UPDATED",
            targetType: "roster_entry",
            targetId: String(entryId),
            metadata: { tabId: Number(entry.tab_id), displayName }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/:entryId", async (req, res) => {
    try {
        const entryId = Number.parseInt(req.params.entryId, 10)
        if (!Number.isInteger(entryId) || entryId <= 0) {
            return res.status(400).json({ error: "Roster entry ID is required" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, tab_id, display_name
                FROM mdt_roster_entries
                WHERE id = ?
                LIMIT 1
            `,
            [entryId]
        )

        if (!rows.length) {
            return res.status(404).json({ error: "Roster entry not found" })
        }

        const entry = rows[0]
        if (!canAccessTab(req.user, entry.tab_id, "edit")) {
            return res.status(403).json({ error: "You do not have edit access to this roster tab" })
        }

        await pool.query(
            `
                UPDATE mdt_roster_entries
                SET is_active = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `,
            [entryId]
        )

        await logAction({
            actor: req.user,
            action: "ROSTER_ENTRY_DELETED",
            targetType: "roster_entry",
            targetId: String(entryId),
            metadata: { tabId: Number(entry.tab_id), displayName: entry.display_name }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/tabs/:tabId/default-group", async (req, res) => {
    try {
        const tabId = Number.parseInt(req.params.tabId, 10)
        const groupId = req.body?.groupId == null || req.body?.groupId === ""
            ? null
            : Number.parseInt(req.body.groupId, 10)

        if (!Number.isInteger(tabId) || tabId <= 0) {
            return res.status(400).json({ error: "Tab ID is required" })
        }

        if (req.user?.role !== "superadmin") {
            return res.status(403).json({ error: "Only superadmins can set roster default groups" })
        }

        if (groupId !== null && (!Number.isInteger(groupId) || groupId <= 0)) {
            return res.status(400).json({ error: "Invalid group" })
        }

        if (groupId !== null) {
            const [groupRows] = await pool.query(
                `
                    SELECT id
                    FROM mdt_groups
                    WHERE id = ?
                    LIMIT 1
                `,
                [groupId]
            )
            if (!groupRows.length) {
                return res.status(404).json({ error: "Group not found" })
            }
        }

        await pool.query(
            `
                UPDATE mdt_tabs
                SET roster_default_group_id = ?
                WHERE id = ?
            `,
            [groupId, tabId]
        )

        await logAction({
            actor: req.user,
            action: "ROSTER_DEFAULT_GROUP_UPDATED",
            targetType: "mdt_tab",
            targetId: String(tabId),
            metadata: { groupId }
        })

        res.json({ success: true, groupId })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
