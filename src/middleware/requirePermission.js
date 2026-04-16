const { userHasPermission } = require("../utils/accessControl")

module.exports = function requirePermission(permission) {
    return (req, res, next) => {
        if (!userHasPermission(req.user, permission)) {
            return res.status(403).json({ error: "Forbidden" })
        }

        next()
    }
}
