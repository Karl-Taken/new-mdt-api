require("dotenv").config()

const express = require("express")
const cors = require("cors")
const helmet = require("helmet")
const { ensureMdtSchema } = require("./bootstrap/mdtSchema")
const healthRoutes = require("./routes/health")
const authRoutes = require("./routes/auth")
const dashboardRoutes = require("./routes/dashboard")
const characterRoutes = require("./routes/characters")
const vehicleRoutes = require("./routes/vehicles")
const incidentRoutes = require("./routes/incidents")
const evidenceRoutes = require("./routes/evidence")
const chargeRoutes = require("./routes/charges")
const announcementRoutes = require("./routes/announcements")
const rosterRoutes = require("./routes/roster")
const accessRoutes = require("./routes/access")
const uploadRoutes = require("./routes/uploads")

const app = express()
const trustProxy = process.env.TRUST_PROXY?.trim()

if (trustProxy) {
    const normalizedTrustProxy = trustProxy.toLowerCase()
    app.set(
        "trust proxy",
        normalizedTrustProxy === "true"
            ? true
            : normalizedTrustProxy === "false"
                ? false
                : /^\d+$/.test(trustProxy)
                    ? Number(trustProxy)
                    : trustProxy
    )
}

app.use(helmet())

const corsOrigin = process.env.CORS_ORIGIN?.trim()
app.use(cors(
    corsOrigin
        ? {
            origin: corsOrigin.split(",").map((origin) => origin.trim()).filter(Boolean)
        }
        : undefined
))

app.use(express.json({ limit: "25mb" }))

app.use("/health", healthRoutes)
app.use("/auth", authRoutes)
app.use("/dashboard", dashboardRoutes)
app.use("/characters", characterRoutes)
app.use("/vehicles", vehicleRoutes)
app.use("/incidents", incidentRoutes)
app.use("/evidence", evidenceRoutes)
app.use("/charges", chargeRoutes)
app.use("/announcements", announcementRoutes)
app.use("/roster", rosterRoutes)
app.use("/access", accessRoutes)
app.use("/uploads", uploadRoutes)

async function start() {
    try {
        await ensureMdtSchema()

        const host = process.env.HOST || "127.0.0.1"
        const port = Number(process.env.PORT || 5100)

        app.listen(port, host, () => {
            console.log(`MDT API running on ${host}:${port}`)
        })
    } catch (error) {
        console.error("Failed to start MDT API", error)
        process.exit(1)
    }
}

start()
