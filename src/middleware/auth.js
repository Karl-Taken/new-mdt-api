const jwt = require("jsonwebtoken")
const { getUserAccessProfile } = require("../utils/accessControl")

module.exports = async (req, res, next) => {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No token provided" })
    }

    const token = authHeader.slice("Bearer ".length)

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        const user = await getUserAccessProfile(decoded.id)

        if (!user) {
            return res.status(403).json({ error: "Access revoked" })
        }

        req.user = user

        next()
    } catch (error) {
        return res.status(403).json({ error: "Invalid token" })
    }
}
