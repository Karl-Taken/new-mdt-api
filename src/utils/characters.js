const { safeJsonParse } = require("./json")

function getCharacterName(charinfo, fallbackName) {
    const fullName = [charinfo?.firstname, charinfo?.lastname].filter(Boolean).join(" ").trim()
    return fullName || fallbackName || "Unknown Character"
}

function serializeCharacterRow(row) {
    const charinfo = safeJsonParse(row.charinfo, {})
    const job = safeJsonParse(row.job, null)
    const gang = safeJsonParse(row.gang, null)
    const metadata = safeJsonParse(row.metadata, {})

    return {
        citizenid: row.citizenid,
        userId: row.userId != null ? Number(row.userId) : null,
        license: row.license || "",
        imageUrl: row.profile_image_url || row.image_url || "",
        name: getCharacterName(charinfo, row.name),
        firstName: charinfo.firstname || "",
        lastName: charinfo.lastname || "",
        dateOfBirth: charinfo.birthdate || "",
        phone: charinfo.phone || "",
        isDead: Boolean(metadata.isdead ?? metadata.dead),
        job: job ? {
            name: job.name || "",
            label: job.label || job.name || ""
        } : null,
        gang: gang ? {
            name: gang.name || "",
            label: gang.label || gang.name || ""
        } : null,
        lastUpdated: row.last_updated || null,
        lastLoggedOut: row.last_logged_out || null
    }
}

module.exports = {
    getCharacterName,
    serializeCharacterRow,
    safeJsonParse
}
