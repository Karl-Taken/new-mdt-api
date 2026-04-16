const LAW_ENFORCEMENT_ROLES = new Set(["law_enforcement", "admin", "superadmin", "officer"])

function normalizeRole(role) {
    const normalized = String(role || "").trim().toLowerCase()
    return normalized === "officer" ? "law_enforcement" : normalized
}

function isLawEnforcement(user) {
    return LAW_ENFORCEMENT_ROLES.has(normalizeRole(user?.role))
}

module.exports = {
    LAW_ENFORCEMENT_ROLES,
    normalizeRole,
    isLawEnforcement
}
