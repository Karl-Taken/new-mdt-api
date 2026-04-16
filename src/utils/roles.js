function normalizeRole(role) {
    const normalized = String(role || "").trim().toLowerCase()
    if (normalized === "officer" || normalized === "law_enforcement") {
        return "user"
    }
    return normalized
}

module.exports = {
    normalizeRole
}
