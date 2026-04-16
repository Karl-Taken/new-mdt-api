const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const { getCharacterName, safeJsonParse } = require("../utils/characters")

const router = express.Router()
router.use(auth)

router.get("/", async (req, res) => {
    try {
        const search = String(req.query.search || "").trim()
        const params = []
        let whereClause = ""

        if (search) {
            const like = `%${search}%`
            whereClause = `
                WHERE pv.plate LIKE ?
                    OR pv.citizenid LIKE ?
                    OR pv.vehicle LIKE ?
                    OR p.name LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.firstname")) LIKE ?
                    OR JSON_UNQUOTE(JSON_EXTRACT(p.charinfo, "$.lastname")) LIKE ?
            `
            params.push(like, like, like, like, like, like)
        }

        const [rows] = await pool.query(
            `
                SELECT pv.id, pv.citizenid, pv.vehicle, pv.plate, pv.garage, pv.state, pv.fuel, pv.engine, pv.body, p.name, p.charinfo
                FROM player_vehicles pv
                LEFT JOIN players p ON p.citizenid = pv.citizenid
                ${whereClause}
                ORDER BY pv.id DESC
                LIMIT 100
            `,
            params
        )

        res.json({
            vehicles: rows.map((row) => ({
                id: Number(row.id),
                citizenid: row.citizenid,
                vehicle: row.vehicle || "",
                plate: row.plate || "",
                garage: row.garage || "",
                state: row.state != null ? Number(row.state) : null,
                fuel: row.fuel != null ? Number(row.fuel) : null,
                engine: row.engine != null ? Number(row.engine) : null,
                body: row.body != null ? Number(row.body) : null,
                ownerName: getCharacterName(safeJsonParse(row.charinfo, {}), row.name)
            }))
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/:plate", async (req, res) => {
    try {
        const plate = String(req.params.plate || "").trim()
        const [rows] = await pool.query(
            `
                SELECT pv.id, pv.citizenid, pv.vehicle, pv.plate, pv.garage, pv.state, pv.fuel, pv.engine, pv.body, pv.mods, p.name, p.charinfo
                FROM player_vehicles pv
                LEFT JOIN players p ON p.citizenid = pv.citizenid
                WHERE pv.plate = ?
                LIMIT 1
            `,
            [plate]
        )

        if (!rows.length) {
            return res.status(404).json({ error: "Vehicle not found" })
        }

        const row = rows[0]
        res.json({
            vehicle: {
                id: Number(row.id),
                citizenid: row.citizenid,
                vehicle: row.vehicle || "",
                plate: row.plate || "",
                garage: row.garage || "",
                state: row.state != null ? Number(row.state) : null,
                fuel: row.fuel != null ? Number(row.fuel) : null,
                engine: row.engine != null ? Number(row.engine) : null,
                body: row.body != null ? Number(row.body) : null,
                mods: row.mods,
                ownerName: getCharacterName(safeJsonParse(row.charinfo, {}), row.name)
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
