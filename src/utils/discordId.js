function normalizeDiscordId(value) {
    const rawValue = String(value || "").trim()
    if (!rawValue) {
        return null
    }

    const match = rawValue.match(/(?:^discord:)?(\d{5,})$/i)
    if (!match) {
        return null
    }

    return match[1]
}

module.exports = {
    normalizeDiscordId
}
