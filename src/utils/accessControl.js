const pool = require("../config/db")
const { normalizeRole } = require("./roles")

const TAB_COMPATIBILITY_PERMISSIONS = {
    dashboard: { view: "dashboard.view" },
    characters: { view: "characters.view" },
    vehicles: { view: "vehicles.view" },
    incidents: { view: "incidents.view", edit: "incidents.edit" },
    medical_reports: { view: "incidents.view", edit: "incidents.edit" },
    evidence: { view: "evidence.view" },
    charges: { view: "charges.view", edit: "charges.edit" },
    announcements: { view: "announcements.view" },
    roster: { view: "roster.view" }
}
const EVERYONE_GROUP_NAME = "@everyone"
const EVERYONE_RANK_NAME = "Everyone"

function safeJsonParse(value, fallbackValue = null) {
    if (value == null || value === "") {
        return fallbackValue
    }

    if (typeof value === "object") {
        return value
    }

    try {
        return JSON.parse(value)
    } catch (_error) {
        return fallbackValue
    }
}

function buildCharacterDisplayName(charinfo, fallbackValue) {
    const firstName = String(charinfo?.firstname || "").trim()
    const lastName = String(charinfo?.lastname || "").trim()
    const fullName = [firstName, lastName].filter(Boolean).join(" ").trim()
    return fullName || String(fallbackValue || "").trim() || null
}

function normalizePermissions(value) {
    if (Array.isArray(value)) {
        return value.map((permission) => String(permission || "").trim()).filter(Boolean)
    }

    if (typeof value === "string" && value.trim()) {
        try {
            const parsed = JSON.parse(value)
            return normalizePermissions(parsed)
        } catch {
            return value.split(",").map((permission) => permission.trim()).filter(Boolean)
        }
    }

    return []
}

function parseBoolean(value) {
    return Number(value || 0) > 0
}

function getCompatibilityPermissionsForTab(tab, access) {
    const mapping = TAB_COMPATIBILITY_PERMISSIONS[tab.tab_key] || TAB_COMPATIBILITY_PERMISSIONS[tab.template_type]
    if (!mapping) {
        return []
    }

    const permissions = []
    if ((access.canView || access.canEdit || access.canManage) && mapping.view) {
        permissions.push(mapping.view)
    }
    if ((access.canEdit || access.canManage) && mapping.edit) {
        permissions.push(mapping.edit)
    }
    return permissions
}

async function getAllActiveTabs() {
    const [rows] = await pool.query(
        `
            SELECT id, tab_key, label, hover_label, path, template_type, group_id, icon_key, is_system, is_active, sort_order
            FROM mdt_tabs
            WHERE is_active = 1
            ORDER BY sort_order ASC, label ASC
        `
    )

    return rows.map((tab) => ({
        id: Number(tab.id),
        key: tab.tab_key,
        label: tab.label,
        hoverLabel: tab.hover_label || "",
        path: tab.path,
        templateType: tab.template_type,
        groupId: tab.group_id ? Number(tab.group_id) : null,
        iconKey: tab.icon_key || null,
        isSystem: parseBoolean(tab.is_system),
        isActive: parseBoolean(tab.is_active)
    }))
}

async function getUserAccessProfile(userId) {
    const [userRows] = await pool.query(
        `
            SELECT mdt_users.id, mdt_users.username, mdt_users.role, mdt_users.is_active, mdt_users.citizenid, mdt_users.display_name,
                   players.charinfo, players.name AS character_name,
                   profiles.image_url AS profile_image_url
            FROM mdt_users
            LEFT JOIN players
                ON players.citizenid = mdt_users.citizenid
            LEFT JOIN mdt_character_profiles AS profiles
                ON profiles.citizenid = mdt_users.citizenid
            WHERE mdt_users.id = ?
            LIMIT 1
        `,
        [userId]
    )

    if (!userRows.length || !userRows[0].is_active) {
        return null
    }

    const user = {
        ...userRows[0],
        role: normalizeRole(userRows[0]?.role)
    }
    const characterInfo = safeJsonParse(user.charinfo, {})
    const displayName = String(user.display_name || "").trim() || buildCharacterDisplayName(characterInfo, user.character_name || user.username)
    const [membershipRows, activeTabs, tabPermissionRows, everyoneRows] = await Promise.all([
        pool.query(
            `
                SELECT
                    membership.id,
                    membership.group_id,
                    membership.rank_id,
                    membership.is_active,
                    groups.name AS group_name,
                    groups.permissions AS group_permissions,
                    ranks.name AS rank_name,
                    ranks.permissions AS rank_permissions
                FROM mdt_user_group_memberships AS membership
                INNER JOIN mdt_groups AS groups
                    ON groups.id = membership.group_id
                INNER JOIN mdt_group_ranks AS ranks
                    ON ranks.id = membership.rank_id
                WHERE membership.user_id = ?
                    AND membership.is_active = 1
                ORDER BY groups.name ASC, ranks.sort_order ASC, ranks.name ASC
            `,
            [userId]
        ),
        getAllActiveTabs(),
        pool.query(
            `
                SELECT
                    permissions.tab_id,
                    permissions.group_id,
                    permissions.rank_id,
                    permissions.can_view,
                    permissions.can_edit,
                    permissions.can_manage
                FROM mdt_tab_rank_permissions AS permissions
                INNER JOIN mdt_user_group_memberships AS membership
                    ON membership.rank_id = permissions.rank_id
                    AND membership.group_id = permissions.group_id
                    AND membership.user_id = ?
                    AND membership.is_active = 1
            `,
            [userId]
        ),
        pool.query(
            `
                SELECT
                    NULL AS id,
                    groups.id AS group_id,
                    ranks.id AS rank_id,
                    1 AS is_active,
                    groups.name AS group_name,
                    groups.permissions AS group_permissions,
                    ranks.name AS rank_name,
                    ranks.permissions AS rank_permissions
                FROM mdt_groups AS groups
                INNER JOIN mdt_group_ranks AS ranks
                    ON ranks.group_id = groups.id
                WHERE groups.name = ?
                    AND ranks.name = ?
                LIMIT 1
            `,
            [EVERYONE_GROUP_NAME, EVERYONE_RANK_NAME]
        )
    ])

    const permissionSet = new Set()
    const resolvedMembershipRows = [...everyoneRows[0], ...membershipRows[0]]
    const memberships = resolvedMembershipRows.map((membership) => {
        const rankPermissions = normalizePermissions(membership.rank_permissions)
        const groupPermissions = normalizePermissions(membership.group_permissions)
        const permissions = Array.from(new Set([...groupPermissions, ...rankPermissions]))
        for (const permission of permissions) {
            permissionSet.add(permission)
        }

        return {
            id: membership.id != null ? Number(membership.id) : null,
            groupId: Number(membership.group_id),
            groupName: membership.group_name,
            rankId: Number(membership.rank_id),
            rankName: membership.rank_name,
            permissions
        }
    })

    const tabAccessMap = new Map()
    for (const tab of activeTabs) {
        tabAccessMap.set(tab.id, {
            tabId: tab.id,
            canView: user.role === "superadmin",
            canEdit: user.role === "superadmin",
            canManage: user.role === "superadmin"
        })
    }

    const everyoneGroupId = Number(everyoneRows[0]?.[0]?.group_id || 0)
    const everyoneRankId = Number(everyoneRows[0]?.[0]?.rank_id || 0)
    const [everyoneTabPermissionRows] = everyoneGroupId && everyoneRankId
        ? await pool.query(
            `
                SELECT
                    tab_id,
                    group_id,
                    rank_id,
                    can_view,
                    can_edit,
                    can_manage
                FROM mdt_tab_rank_permissions
                WHERE group_id = ?
                    AND rank_id = ?
            `,
            [everyoneGroupId, everyoneRankId]
        )
        : [[]]
    const resolvedTabPermissionRows = [...everyoneTabPermissionRows, ...tabPermissionRows[0]]

    for (const row of resolvedTabPermissionRows) {
        const tabId = Number(row.tab_id)
        const current = tabAccessMap.get(tabId) || {
            tabId,
            canView: false,
            canEdit: false,
            canManage: false
        }
        current.canView = current.canView || parseBoolean(row.can_view) || parseBoolean(row.can_edit) || parseBoolean(row.can_manage)
        current.canEdit = current.canEdit || parseBoolean(row.can_edit) || parseBoolean(row.can_manage)
        current.canManage = current.canManage || parseBoolean(row.can_manage)
        tabAccessMap.set(tabId, current)
    }

    const tabs = activeTabs.map((tab) => {
        const access = tabAccessMap.get(tab.id) || { canView: false, canEdit: false, canManage: false }
        for (const permission of getCompatibilityPermissionsForTab({ tab_key: tab.key, template_type: tab.templateType }, access)) {
            permissionSet.add(permission)
        }

        return {
            ...tab,
            access
        }
    })

    if (normalizeRole(user.role) === "superadmin") {
        permissionSet.add("*")
    }

    return {
        id: Number(user.id),
        username: user.username,
        citizenid: user.citizenid || null,
        firstName: characterInfo?.firstname || null,
        lastName: characterInfo?.lastname || null,
        displayName,
        imageUrl: user.profile_image_url || null,
        role: normalizeRole(user.role),
        permissions: Array.from(permissionSet),
        memberships,
        tabs
    }
}

function userHasPermission(user, permission) {
    if (!user) {
        return false
    }

    if (normalizeRole(user.role) === "superadmin") {
        return true
    }

    const permissions = Array.isArray(user.permissions) ? user.permissions : []
    return permissions.includes("*") || permissions.includes(permission)
}

module.exports = {
    getAllActiveTabs,
    getUserAccessProfile,
    userHasPermission,
    normalizePermissions
}
