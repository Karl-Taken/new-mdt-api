function safeJsonParse(value, fallback = null) {
    if (!value) {
        return fallback
    }

    try {
        return JSON.parse(value)
    } catch (error) {
        return fallback
    }
}

module.exports = {
    safeJsonParse
}
