const express = require("express")
const bcrypt = require("bcrypt")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const requireRole = require("../middleware/requireRole")
const logAction = require("../utils/auditLogger")
const { normalizePermissions, getAllActiveTabs } = require("../utils/accessControl")
const { normalizeDiscordId } = require("../utils/discordId")

const router = express.Router()
router.use(auth)
const AVAILABLE_PERMISSIONS = [
    {
        key: "dashboard.view",
        label: "Dashboard Tab",
        description: "View the dashboard tab."
    },
    {
        key: "characters.view",
        label: "Citizen Tab",
        description: "View citizen records."
    },
    {
        key: "vehicles.view",
        label: "Vehicles Tab",
        description: "View vehicle records."
    },
    {
        key: "incidents.view",
        label: "Incidents Tab",
        description: "View incident reports."
    },
    {
        key: "incidents.edit",
        label: "Incident Editing",
        description: "Create and edit incident reports."
    },
    {
        key: "evidence.view",
        label: "Evidence Tab",
        description: "View evidence records."
    },
    {
        key: "charges.view",
        label: "Charges Tab",
        description: "View the penal code directory."
    },
    {
        key: "charges.create.view",
        label: "Create Charge Tab",
        description: "View the create charge workspace from the penal code menu."
    },
    {
        key: "charges.edit",
        label: "Charge Editing",
        description: "Create and edit charges and penal code definitions."
    },
    {
        key: "announcements.view",
        label: "Announcements Tab",
        description: "View announcements."
    },
    {
        key: "roster.view",
        label: "Roster Tab",
        description: "View the live roster."
    }
]
const AVAILABLE_TAB_TEMPLATES = [
    {
        key: "dashboard",
        label: "Dashboard",
        description: "Group-specific dashboard overview and scoped activity."
    },
    {
        key: "incidents",
        label: "Incident Workspace",
        description: "Case building, reports, people, and evidence."
    },
    {
        key: "medical_reports",
        label: "Medical Reports",
        description: "Medical treatment, autopsy, and generic report workspace."
    },
    {
        key: "roster",
        label: "Roster",
        description: "Department roster and personnel entries."
    },
    {
        key: "announcements",
        label: "Announcements",
        description: "Group-specific notices and internal bulletins."
    }
]
const RESERVED_GROUP_NAMES = new Set(["@everyone"])

function getManageableTabsForUser(user) {
    if (user?.role === "superadmin") {
        return null
    }

    return (user?.tabs || []).filter((tab) => tab?.access?.canManage && !tab?.isSystem)
}

function getManageableTabIdsForUser(user) {
    const tabs = getManageableTabsForUser(user)
    return tabs ? new Set(tabs.map((tab) => Number(tab.id))) : null
}

async function getTabForPermissionManagement(user, tabId) {
    const [tabRows] = await pool.query(
        `
            SELECT id, group_id, is_system
            FROM mdt_tabs
            WHERE id = ?
            LIMIT 1
        `,
        [tabId]
    )

    if (!tabRows.length) {
        return { error: "Tab not found", status: 404 }
    }

    const tab = tabRows[0]
    if (user?.role === "superadmin") {
        return { tab }
    }

    if (Number(tab.is_system || 0) > 0) {
        return { error: "Only superadmins can manage system tabs", status: 403 }
    }

    const manageableTabIds = getManageableTabIdsForUser(user)
    if (!manageableTabIds?.has(Number(tab.id))) {
        return { error: "You do not have permission to manage this tab", status: 403 }
    }

    return { tab }
}

function normalizeTabKey(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 100)
}

function buildGroupTabPath(groupName, templateType, tabKey) {
    return `/groups/${normalizeTabKey(groupName)}/${templateType}/${tabKey}`
}

async function createManagedTab({ group, label, templateType }) {
    const tabKey = normalizeTabKey(`${group.name}-${label}-${group.id}`)
    const path = buildGroupTabPath(group.name, templateType, tabKey)

    await pool.query(
        `
            INSERT INTO mdt_tabs (tab_key, label, path, template_type, group_id, icon_key, is_system, is_active, sort_order)
            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                0,
                1,
                (
                    SELECT COALESCE(MAX(existing.sort_order), 0) + 1
                    FROM mdt_tabs AS existing
                )
            )
        `,
        [tabKey, label, path, templateType, group.id, templateType]
    )

    return { tabKey, path }
}

async function ensureGroupAnnouncementTab(group) {
    const [existingRows] = await pool.query(
        `
            SELECT id
            FROM mdt_tabs
            WHERE group_id = ?
                AND template_type = 'announcements'
                AND is_active = 1
            LIMIT 1
        `,
        [group.id]
    )

    if (existingRows.length) {
        return existingRows[0]
    }

    return createManagedTab({ group, label: `${group.name} Announcements`, templateType: "announcements" })
}

async function updateTabMetadata(tabId, values) {
    await pool.query(
        `
            UPDATE mdt_tabs
            SET label = ?,
                hover_label = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `,
        [values.label, values.hoverLabel, tabId]
    )
}

router.get("/overview", async (req, res) => {
    try {
        const [groupRows, rankRows, userRows, membershipRows, tabs, tabPermissions] = await Promise.all([
            pool.query(
                `
                    SELECT id, name, description, permissions
                    FROM mdt_groups
                    ORDER BY name ASC
                `
            ),
            pool.query(
                `
                    SELECT id, group_id, name, permissions, sort_order
                    FROM mdt_group_ranks
                    ORDER BY group_id ASC, sort_order ASC, name ASC
                `
            ),
            pool.query(
                `
                    SELECT id, username, role, is_active, last_login_at
                           , discord_id
                    FROM mdt_users
                    ORDER BY username ASC
                `
            ),
            pool.query(
                `
                    SELECT id, user_id, group_id, rank_id, is_active
                    FROM mdt_user_group_memberships
                    ORDER BY user_id ASC, group_id ASC
                `
            ),
            getAllActiveTabs(),
            pool.query(
                `
                    SELECT id, tab_id, group_id, rank_id, can_view, can_edit, can_manage
                    FROM mdt_tab_rank_permissions
                    ORDER BY tab_id ASC, group_id ASC, rank_id ASC
                `
            )
        ])

        const manageableTabIds = getManageableTabIdsForUser(req.user)
        const visibleTabs = manageableTabIds
            ? tabs.filter((tab) => manageableTabIds.has(Number(tab.id)))
            : tabs
        const visibleGroupIds = new Set(
            visibleTabs
                .map((tab) => Number(tab.groupId || 0))
                .filter((groupId) => groupId > 0)
        )
        const visibleRanks = manageableTabIds
            ? rankRows[0].filter((rank) => visibleGroupIds.has(Number(rank.group_id)))
            : rankRows[0]
        const visibleUsers = manageableTabIds
            ? []
            : userRows[0]
        const visibleMemberships = manageableTabIds
            ? membershipRows[0].filter((membership) => visibleGroupIds.has(Number(membership.group_id)))
            : membershipRows[0]
        const visibleGroups = manageableTabIds
            ? groupRows[0].filter((group) => visibleGroupIds.has(Number(group.id)))
            : groupRows[0]
        const visibleTabPermissions = manageableTabIds
            ? tabPermissions[0].filter((permission) => manageableTabIds.has(Number(permission.tab_id)))
            : tabPermissions[0]

        res.json({
            groups: visibleGroups.map((group) => ({
                ...group,
                permissions: normalizePermissions(group.permissions)
            })),
            ranks: visibleRanks.map((rank) => ({
                ...rank,
                permissions: normalizePermissions(rank.permissions)
            })),
            users: visibleUsers,
            memberships: visibleMemberships,
            permissions: AVAILABLE_PERMISSIONS,
            tabs: visibleTabs,
            tabPermissions: visibleTabPermissions,
            tabTemplates: AVAILABLE_TAB_TEMPLATES
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/tabs", requireRole(["superadmin"]), async (req, res) => {
    try {
        const label = String(req.body?.label || "").trim()
        const templateType = String(req.body?.templateType || "").trim().toLowerCase()
        const groupId = Number.parseInt(req.body?.groupId, 10)

        if (!label) {
            return res.status(400).json({ error: "Tab label is required" })
        }

        if (!AVAILABLE_TAB_TEMPLATES.some((template) => template.key === templateType)) {
            return res.status(400).json({ error: "A valid tab template is required" })
        }

        if (!Number.isInteger(groupId) || groupId <= 0) {
            return res.status(400).json({ error: "Group is required" })
        }

        const [groupRows] = await pool.query(
            "SELECT id, name FROM mdt_groups WHERE id = ? LIMIT 1",
            [groupId]
        )

        if (!groupRows.length) {
            return res.status(404).json({ error: "Group not found" })
        }

        const group = groupRows[0]
        const { tabKey: tabKeyBase } = await createManagedTab({ group, label, templateType })
        if (templateType === "dashboard") {
            await ensureGroupAnnouncementTab(group)
        }

        await logAction({
            actor: req.user,
            action: "TAB_CREATED",
            targetType: "mdt_tab",
            targetId: tabKeyBase,
            metadata: {
                label,
                templateType,
                groupId
            }
        })

        res.json({ success: true })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "A tab with that generated key already exists. Try a different label." })
        }

        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/tabs/:tabId", requireRole(["superadmin"]), async (req, res) => {
    try {
        const tabId = Number.parseInt(req.params.tabId, 10)
        if (!Number.isInteger(tabId) || tabId <= 0) {
            return res.status(400).json({ error: "Tab ID is required" })
        }

        const [tabRows] = await pool.query(
            `
                SELECT id, label, tab_key, is_system
                FROM mdt_tabs
                WHERE id = ?
                LIMIT 1
            `,
            [tabId]
        )

        if (!tabRows.length) {
            return res.status(404).json({ error: "Tab not found" })
        }

        const tab = tabRows[0]
        if (Number(tab.is_system || 0) > 0) {
            return res.status(403).json({ error: "System tabs cannot be deleted" })
        }

        await pool.query(
            `
                UPDATE mdt_tabs
                SET is_active = 0
                WHERE id = ?
            `,
            [tabId]
        )
        await pool.query("DELETE FROM mdt_tab_rank_permissions WHERE tab_id = ?", [tabId])

        await logAction({
            actor: req.user,
            action: "TAB_DELETED",
            targetType: "mdt_tab",
            targetId: String(tabId),
            metadata: {
                label: tab.label,
                tabKey: tab.tab_key
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/tabs/:tabId", async (req, res) => {
    try {
        const tabId = Number.parseInt(req.params.tabId, 10)
        if (!Number.isInteger(tabId) || tabId <= 0) {
            return res.status(400).json({ error: "Tab ID is required" })
        }

        const label = String(req.body?.label || "").trim()
        const hoverLabel = String(req.body?.hoverLabel || "").trim() || null

        if (!label) {
            return res.status(400).json({ error: "Tab title is required" })
        }

        const { tab, error: tabError, status } = await getTabForPermissionManagement(req.user, tabId)
        if (tabError) {
            return res.status(status).json({ error: tabError })
        }

        await updateTabMetadata(tabId, { label, hoverLabel })

        await logAction({
            actor: req.user,
            action: "TAB_UPDATED",
            targetType: "mdt_tab",
            targetId: String(tabId),
            metadata: {
                label,
                hoverLabel
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/tabs/:tabId/permissions", async (req, res) => {
    try {
        const tabId = Number.parseInt(req.params.tabId, 10)
        const assignments = Array.isArray(req.body?.assignments) ? req.body.assignments : []

        if (!Number.isInteger(tabId) || tabId <= 0) {
            return res.status(400).json({ error: "Tab ID is required" })
        }

        const { tab, error: tabError, status } = await getTabForPermissionManagement(req.user, tabId)
        if (tabError) {
            return res.status(status).json({ error: tabError })
        }

        await pool.query("DELETE FROM mdt_tab_rank_permissions WHERE tab_id = ?", [tabId])

        for (const assignment of assignments) {
            const groupId = Number.parseInt(assignment?.groupId, 10)
            const rankId = Number.parseInt(assignment?.rankId, 10)
            const canView = assignment?.canManage ? 1 : assignment?.canEdit ? 1 : assignment?.canView ? 1 : 0
            const canEdit = assignment?.canManage ? 1 : assignment?.canEdit ? 1 : 0
            const canManage = assignment?.canManage ? 1 : 0

            if (!Number.isInteger(groupId) || groupId <= 0 || !Number.isInteger(rankId) || rankId <= 0) {
                continue
            }

            if (req.user?.role !== "superadmin" && Number(tab.group_id || 0) !== groupId) {
                continue
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

            if (!rankRows.length) {
                continue
            }

            const rank = rankRows[0]
            if (Number(rank.group_id || 0) !== groupId) {
                continue
            }

            await pool.query(
                `
                    INSERT INTO mdt_tab_rank_permissions (tab_id, group_id, rank_id, can_view, can_edit, can_manage)
                    VALUES (?, ?, ?, ?, ?, ?)
                `,
                [tabId, groupId, rankId, canView, canEdit, canManage]
            )
        }

        await logAction({
            actor: req.user,
            action: "TAB_PERMISSIONS_UPDATED",
            targetType: "mdt_tab",
            targetId: String(tabId)
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/groups", requireRole(["superadmin"]), async (req, res) => {
    try {
        const name = String(req.body?.name || "").trim()
        const description = String(req.body?.description || "").trim() || null

        if (!name) {
            return res.status(400).json({ error: "Group name is required" })
        }

        if (RESERVED_GROUP_NAMES.has(name.toLowerCase())) {
            return res.status(400).json({ error: "That group name is reserved" })
        }

        const [result] = await pool.query(
            `
                INSERT INTO mdt_groups (name, description, permissions)
                VALUES (?, ?, ?)
            `,
            [name, description, JSON.stringify([])]
        )

        let groupId = Number(result?.insertId || 0)
        if (!groupId) {
            const [groupRows] = await pool.query(
                "SELECT id, name FROM mdt_groups WHERE name = ? LIMIT 1",
                [name]
            )
            groupId = Number(groupRows[0]?.id || 0)
        }

        const group = { id: groupId, name }

        await createManagedTab({ group, label: `${name} Dashboard`, templateType: "dashboard" })
        await createManagedTab({ group, label: `${name} Reports`, templateType: "incidents" })
        await createManagedTab({ group, label: `${name} Roster`, templateType: "roster" })
        await createManagedTab({ group, label: `${name} Announcements`, templateType: "announcements" })

        await logAction({
            actor: req.user,
            action: "ACCESS_GROUP_CREATED",
            targetType: "access_group",
            targetId: name,
            metadata: {
                groupId
            }
        })

        res.json({ success: true })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "A group with that name already exists" })
        }

        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/groups/:groupId/permissions", requireRole(["superadmin"]), async (req, res) => {
    try {
        const groupId = Number.parseInt(req.params.groupId, 10)
        const permissions = normalizePermissions(req.body?.permissions)

        if (!Number.isInteger(groupId) || groupId <= 0) {
            return res.status(400).json({ error: "Group ID is required" })
        }

        await pool.query(
            `
                UPDATE mdt_groups
                SET permissions = ?
                WHERE id = ?
            `,
            [JSON.stringify(permissions), groupId]
        )

        await logAction({
            actor: req.user,
            action: "ACCESS_GROUP_PERMISSIONS_UPDATED",
            targetType: "access_group",
            targetId: String(groupId),
            metadata: { permissions }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/groups/:groupId", requireRole(["superadmin"]), async (req, res) => {
    try {
        const groupId = Number.parseInt(req.params.groupId, 10)
        const name = String(req.body?.name || "").trim()
        const description = String(req.body?.description || "").trim()

        if (!Number.isInteger(groupId) || groupId <= 0) {
            return res.status(400).json({ error: "Group ID is required" })
        }

        if (!name) {
            return res.status(400).json({ error: "Group name is required" })
        }

        if (RESERVED_GROUP_NAMES.has(name.toLowerCase())) {
            return res.status(400).json({ error: "That group name is reserved" })
        }

        await pool.query(
            `
                UPDATE mdt_groups
                SET name = ?, description = ?
                WHERE id = ?
            `,
            [name, description || null, groupId]
        )

        await logAction({
            actor: req.user,
            action: "ACCESS_GROUP_UPDATED",
            targetType: "access_group",
            targetId: String(groupId),
            metadata: { name, description }
        })

        res.json({ success: true })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "A group with that name already exists" })
        }

        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/groups/:groupId/ranks", requireRole(["superadmin"]), async (req, res) => {
    try {
        const groupId = Number.parseInt(req.params.groupId, 10)
        const name = String(req.body?.name || "").trim()
        const permissions = normalizePermissions(req.body?.permissions)

        if (!Number.isInteger(groupId) || groupId <= 0) {
            return res.status(400).json({ error: "Group ID is required" })
        }

        if (!name) {
            return res.status(400).json({ error: "Rank name is required" })
        }

        const [groupRows] = await pool.query(
            "SELECT id, name FROM mdt_groups WHERE id = ? LIMIT 1",
            [groupId]
        )

        if (!groupRows.length) {
            return res.status(404).json({ error: "Group not found" })
        }

        await pool.query(
            `
                INSERT INTO mdt_group_ranks (group_id, name, permissions, sort_order)
                VALUES (
                    ?,
                    ?,
                    ?,
                    (
                        SELECT COALESCE(MAX(existing.sort_order), 0) + 1
                        FROM mdt_group_ranks AS existing
                        WHERE existing.group_id = ?
                    )
                )
            `,
            [groupId, name, JSON.stringify(permissions), groupId]
        )

        await logAction({
            actor: req.user,
            action: "ACCESS_RANK_CREATED",
            targetType: "access_rank",
            targetId: name,
            metadata: {
                groupId,
                permissions
            }
        })

        res.json({ success: true })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "A rank with that name already exists in this group" })
        }

        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/ranks/:rankId", requireRole(["superadmin"]), async (req, res) => {
    try {
        const rankId = Number.parseInt(req.params.rankId, 10)
        const name = String(req.body?.name || "").trim()
        const permissions = normalizePermissions(req.body?.permissions)

        if (!Number.isInteger(rankId) || rankId <= 0) {
            return res.status(400).json({ error: "Rank ID is required" })
        }

        if (!name) {
            return res.status(400).json({ error: "Rank name is required" })
        }

        await pool.query(
            `
                UPDATE mdt_group_ranks
                SET name = ?, permissions = ?
                WHERE id = ?
            `,
            [name, JSON.stringify(permissions), rankId]
        )

        await logAction({
            actor: req.user,
            action: "ACCESS_RANK_UPDATED",
            targetType: "access_rank",
            targetId: String(rankId),
            metadata: { permissions }
        })

        res.json({ success: true })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "A rank with that name already exists in this group" })
        }

        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/users", requireRole(["superadmin"]), async (req, res) => {
    try {
        const username = String(req.body?.username || "").trim()
        const password = String(req.body?.password || "")
        const role = String(req.body?.role || "user").trim()
        const rawDiscordId = req.body?.discordId
        const discordId = rawDiscordId == null || String(rawDiscordId).trim() === ""
            ? null
            : normalizeDiscordId(rawDiscordId)

        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required" })
        }

        if (rawDiscordId != null && String(rawDiscordId).trim() !== "" && !discordId) {
            return res.status(400).json({ error: "Discord ID must be a valid Discord snowflake" })
        }

        if (!["user", "law_enforcement", "admin", "superadmin"].includes(role)) {
            return res.status(400).json({ error: "Invalid role" })
        }

        const passwordHash = await bcrypt.hash(password, 10)
        await pool.query(
            `
                INSERT INTO mdt_users (username, password_hash, role, discord_id)
                VALUES (?, ?, ?, ?)
            `,
            [username, passwordHash, role, discordId]
        )

        await logAction({
            actor: req.user,
            action: "ACCESS_USER_CREATED",
            targetType: "mdt_user",
            targetId: username,
            metadata: { role, discordId }
        })

        res.json({ success: true })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "A user with that username already exists" })
        }

        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/users/:userId/memberships", requireRole(["superadmin"]), async (req, res) => {
    try {
        const userId = Number.parseInt(req.params.userId, 10)
        const rankId = Number.parseInt(req.body?.rankId, 10)

        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: "User ID is required" })
        }

        if (!Number.isInteger(rankId) || rankId <= 0) {
            return res.status(400).json({ error: "Rank ID is required" })
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

        if (!rankRows.length) {
            return res.status(404).json({ error: "Rank not found" })
        }

        const rank = rankRows[0]
        await pool.query(
            `
                INSERT INTO mdt_user_group_memberships (user_id, group_id, rank_id, is_active)
                VALUES (?, ?, ?, 1)
                ON DUPLICATE KEY UPDATE rank_id = VALUES(rank_id), is_active = 1
            `,
            [userId, rank.group_id, rankId]
        )

        await logAction({
            actor: req.user,
            action: "ACCESS_USER_ASSIGNED_RANK",
            targetType: "mdt_user",
            targetId: String(userId),
            metadata: {
                groupId: rank.group_id,
                rankId
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/users/:userId", requireRole(["superadmin"]), async (req, res) => {
    try {
        const userId = Number.parseInt(req.params.userId, 10)
        const username = String(req.body?.username || "").trim()
        const password = String(req.body?.password || "")
        const role = String(req.body?.role || "user").trim()
        const isActive = req.body?.isActive === false ? 0 : 1
        const rawDiscordId = req.body?.discordId
        const discordId = rawDiscordId == null || String(rawDiscordId).trim() === ""
            ? null
            : normalizeDiscordId(rawDiscordId)

        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: "User ID is required" })
        }

        if (!username) {
            return res.status(400).json({ error: "Username is required" })
        }

        if (!["user", "law_enforcement", "admin", "superadmin"].includes(role)) {
            return res.status(400).json({ error: "Invalid role" })
        }

        if (rawDiscordId != null && String(rawDiscordId).trim() !== "" && !discordId) {
            return res.status(400).json({ error: "Discord ID must be a valid Discord snowflake" })
        }

        const [existingRows] = await pool.query(
            `
                SELECT id
                FROM mdt_users
                WHERE id = ?
                LIMIT 1
            `,
            [userId]
        )

        if (!existingRows.length) {
            return res.status(404).json({ error: "User not found" })
        }

        if (password) {
            const passwordHash = await bcrypt.hash(password, 10)
            await pool.query(
                `
                    UPDATE mdt_users
                    SET username = ?, role = ?, is_active = ?, discord_id = ?, password_hash = ?
                    WHERE id = ?
                `,
                [username, role, isActive, discordId, passwordHash, userId]
            )
        } else {
            await pool.query(
                `
                    UPDATE mdt_users
                    SET username = ?, role = ?, is_active = ?, discord_id = ?
                    WHERE id = ?
                `,
                [username, role, isActive, discordId, userId]
            )
        }

        await logAction({
            actor: req.user,
            action: "ACCESS_USER_UPDATED",
            targetType: "mdt_user",
            targetId: String(userId),
            metadata: { username, role, isActive: Boolean(isActive), discordId, passwordChanged: Boolean(password) }
        })

        res.json({ success: true })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "A user with that username already exists" })
        }

        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/users/:userId/memberships", requireRole(["superadmin"]), async (req, res) => {
    try {
        const userId = Number.parseInt(req.params.userId, 10)
        const memberships = Array.isArray(req.body?.memberships) ? req.body.memberships : []

        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: "User ID is required" })
        }

        const rankIds = memberships
            .map((membership) => Number.parseInt(membership?.rankId, 10))
            .filter((rankId) => Number.isInteger(rankId) && rankId > 0)

        const [rankRows] = rankIds.length
            ? await pool.query(
                `
                    SELECT id, group_id
                    FROM mdt_group_ranks
                    WHERE id IN (?)
                `,
                [rankIds]
            )
            : [[]]

        if (rankIds.length && rankRows.length !== rankIds.length) {
            return res.status(404).json({ error: "One or more selected ranks were not found" })
        }

        await pool.query("DELETE FROM mdt_user_group_memberships WHERE user_id = ?", [userId])

        for (const rank of rankRows) {
            await pool.query(
                `
                    INSERT INTO mdt_user_group_memberships (user_id, group_id, rank_id, is_active)
                    VALUES (?, ?, ?, 1)
                `,
                [userId, rank.group_id, rank.id]
            )
        }

        await logAction({
            actor: req.user,
            action: "ACCESS_USER_MEMBERSHIPS_REPLACED",
            targetType: "mdt_user",
            targetId: String(userId),
            metadata: { rankIds }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
