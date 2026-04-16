function normalizeIp(ipAddress) {
    const value = String(ipAddress || "").trim()
    if (!value) {
        return ""
    }

    if (value.startsWith("::ffff:")) {
        return value.slice("::ffff:".length)
    }

    return value
}

function getClientIp(req) {
    return normalizeIp(req.ip || req.socket?.remoteAddress)
}

module.exports = {
    getClientIp
}
