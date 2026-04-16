const express = require("express")
const pool = require("../config/db")
const auth = require("../middleware/auth")
const requireRole = require("../middleware/requireRole")
const requirePermission = require("../middleware/requirePermission")
const logAction = require("../utils/auditLogger")

const router = express.Router()
const VALID_ENHANCEMENT_COLORS = new Set(["neutral", "red", "green", "yellow", "orange"])

function sanitizeEnhancements(input) {
    if (!Array.isArray(input)) {
        return []
    }

    return input
        .map((item, index) => ({
            label: String(item?.label || "").trim(),
            color: String(item?.color || "neutral").trim().toLowerCase(),
            finePercentOff: Number(item?.finePercentOff || 0),
            jailPercentOff: Number(item?.jailPercentOff || 0),
            displayOrder: index
        }))
        .filter((item) => item.label)
        .map((item) => ({
            ...item,
            color: VALID_ENHANCEMENT_COLORS.has(item.color) ? item.color : "neutral",
            finePercentOff: Math.min(Math.max(item.finePercentOff, 0), 100),
            jailPercentOff: Math.min(Math.max(item.jailPercentOff, 0), 100)
        }))
}

async function replaceChargeEnhancements(chargeId, enhancements) {
    await pool.query(
        "DELETE FROM mdt_penal_code_charge_enhancements WHERE charge_id = ?",
        [chargeId]
    )

    for (const enhancement of enhancements) {
        await pool.query(
            `
                INSERT INTO mdt_penal_code_charge_enhancements (charge_id, label, color, fine_percent_off, jail_percent_off, display_order)
                VALUES (?, ?, ?, ?, ?, ?)
            `,
            [
                chargeId,
                enhancement.label,
                enhancement.color,
                enhancement.finePercentOff,
                enhancement.jailPercentOff,
                enhancement.displayOrder
            ]
        )
    }
}

async function ensureCategoryExists(name, kind = "title") {
    const trimmedName = String(name || "").trim()
    if (!trimmedName) {
        return null
    }

    const [maxRows] = await pool.query(
        `
            SELECT COALESCE(MAX(sort_order), 0) AS maxSortOrder
            FROM mdt_penal_code_categories
        `
    )

    await pool.query(
        `
            INSERT INTO mdt_penal_code_categories (name, kind, sort_order)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE kind = kind
        `,
        [trimmedName, kind, Number(maxRows[0]?.maxSortOrder || 0) + 1]
    )

    const [rows] = await pool.query(
        `
            SELECT id, name, kind, sort_order
            FROM mdt_penal_code_categories
            WHERE name = ?
            LIMIT 1
        `,
        [trimmedName]
    )

    return rows[0] || null
}

async function swapCategorySortOrder(firstCategory, secondCategory) {
    await pool.query(
        `
            UPDATE mdt_penal_code_categories
            SET sort_order = ?
            WHERE id = ?
        `,
        [secondCategory.sort_order, firstCategory.id]
    )

    await pool.query(
        `
            UPDATE mdt_penal_code_categories
            SET sort_order = ?
            WHERE id = ?
        `,
        [firstCategory.sort_order, secondCategory.id]
    )
}

async function getChargeDirectoryPayload() {
    const [chargeRows, categoryRows, definitionRows, enhancementRows] = await Promise.all([
        pool.query(
            `
                SELECT id, title, code, category, class, fine, jail_time, points, description
                FROM mdt_penal_code_charges
                ORDER BY category ASC, title ASC
            `
        ),
        pool.query(
            `
                SELECT id, name, kind, sort_order
                FROM mdt_penal_code_categories
                ORDER BY sort_order ASC, name ASC
            `
        ),
        pool.query(
            `
                SELECT id, category_id, code, name, definition
                FROM mdt_penal_code_definitions
                ORDER BY code ASC, name ASC
            `
        ),
        pool.query(
            `
                SELECT id, charge_id, label, color, fine_percent_off, jail_percent_off, display_order
                FROM mdt_penal_code_charge_enhancements
                ORDER BY charge_id ASC, display_order ASC, id ASC
            `
        )
    ])

    return {
        charges: chargeRows[0],
        categories: categoryRows[0],
        definitions: definitionRows[0],
        enhancements: enhancementRows[0]
    }
}

router.get("/public", async (req, res) => {
    try {
        res.json(await getChargeDirectoryPayload())
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/", auth, async (req, res) => {
    try {
        res.json(await getChargeDirectoryPayload())
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/categories", auth, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
                SELECT id, name, kind, sort_order
                FROM mdt_penal_code_categories
                ORDER BY sort_order ASC, name ASC
            `
        )

        res.json({ categories: rows })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/categories", auth, requireRole(["superadmin"]), async (req, res) => {
    try {
        const name = String(req.body?.name || "").trim()
        const kind = "title"

        if (!name) {
            return res.status(400).json({ error: "Category name is required" })
        }

        const [existingRows] = await pool.query(
            "SELECT id FROM mdt_penal_code_categories WHERE name = ? LIMIT 1",
            [name]
        )

        if (existingRows.length) {
            return res.status(409).json({ error: "A title with that name already exists" })
        }

        await pool.query(
            `
                INSERT INTO mdt_penal_code_categories (name, kind, sort_order)
                VALUES (?, ?, (
                    SELECT COALESCE(MAX(existing.sort_order), 0) + 1
                    FROM mdt_penal_code_categories AS existing
                ))
            `,
            [name, kind]
        )

        await logAction({
            actor: req.user,
            action: "CHARGE_CATEGORY_CREATED",
            targetType: "charge_category",
            targetId: name,
            metadata: { kind }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/categories/:categoryId", auth, requireRole(["superadmin"]), async (req, res) => {
    try {
        const categoryId = Number.parseInt(req.params.categoryId, 10)
        const name = String(req.body?.name || "").trim()

        if (!Number.isInteger(categoryId) || categoryId <= 0) {
            return res.status(400).json({ error: "Category ID is required" })
        }

        if (!name) {
            return res.status(400).json({ error: "Title name is required" })
        }

        const [categoryRows] = await pool.query(
            `
                SELECT id, name, kind, sort_order
                FROM mdt_penal_code_categories
                WHERE id = ?
                LIMIT 1
            `,
            [categoryId]
        )

        if (!categoryRows.length) {
            return res.status(404).json({ error: "Title not found" })
        }

        const category = categoryRows[0]
        const [existingRows] = await pool.query(
            `
                SELECT id
                FROM mdt_penal_code_categories
                WHERE name = ?
                    AND id != ?
                LIMIT 1
            `,
            [name, categoryId]
        )

        if (existingRows.length) {
            return res.status(409).json({ error: "A title with that name already exists" })
        }

        await pool.query(
            `
                UPDATE mdt_penal_code_categories
                SET name = ?, kind = 'title'
                WHERE id = ?
            `,
            [name, categoryId]
        )

        await pool.query(
            `
                UPDATE mdt_penal_code_charges
                SET category = ?
                WHERE category = ?
            `,
            [name, category.name]
        )

        await logAction({
            actor: req.user,
            action: "CHARGE_CATEGORY_UPDATED",
            targetType: "charge_category",
            targetId: String(categoryId),
            metadata: {
                previousName: category.name,
                nextName: name
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/categories/:categoryId/move", auth, requireRole(["superadmin"]), async (req, res) => {
    try {
        const categoryId = Number.parseInt(req.params.categoryId, 10)
        const direction = String(req.body?.direction || "").trim().toLowerCase()

        if (!Number.isInteger(categoryId) || categoryId <= 0) {
            return res.status(400).json({ error: "Category ID is required" })
        }

        if (!["up", "down"].includes(direction)) {
            return res.status(400).json({ error: "Direction must be up or down" })
        }

        const [categoryRows] = await pool.query(
            `
                SELECT id, name, sort_order
                FROM mdt_penal_code_categories
                WHERE id = ?
                LIMIT 1
            `,
            [categoryId]
        )

        if (!categoryRows.length) {
            return res.status(404).json({ error: "Title not found" })
        }

        const category = categoryRows[0]
        const operator = direction === "up" ? "<" : ">"
        const sortDirection = direction === "up" ? "DESC" : "ASC"
        const [swapRows] = await pool.query(
            `
                SELECT id, name, sort_order
                FROM mdt_penal_code_categories
                WHERE sort_order ${operator} ?
                ORDER BY sort_order ${sortDirection}
                LIMIT 1
            `,
            [category.sort_order]
        )

        if (!swapRows.length) {
            return res.json({ success: true, moved: false })
        }

        await swapCategorySortOrder(category, swapRows[0])

        await logAction({
            actor: req.user,
            action: "CHARGE_CATEGORY_REORDERED",
            targetType: "charge_category",
            targetId: String(categoryId),
            metadata: {
                direction,
                swappedWith: swapRows[0].id
            }
        })

        res.json({ success: true, moved: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/categories/:categoryId/definitions", auth, requirePermission("charges.edit"), async (req, res) => {
    try {
        const categoryId = Number.parseInt(req.params.categoryId, 10)
        const code = String(req.body?.code || "").trim()
        const name = String(req.body?.name || "").trim()
        const definition = String(req.body?.definition || "").trim()

        if (!Number.isInteger(categoryId) || categoryId <= 0) {
            return res.status(400).json({ error: "Category ID is required" })
        }

        if (!code || !name || !definition) {
            return res.status(400).json({ error: "Code, name, and definition are required" })
        }

        const [categoryRows] = await pool.query(
            `
                SELECT id, name
                FROM mdt_penal_code_categories
                WHERE id = ?
                LIMIT 1
            `,
            [categoryId]
        )

        if (!categoryRows.length) {
            return res.status(404).json({ error: "Title not found" })
        }

        const [existingRows] = await pool.query(
            `
                SELECT id
                FROM mdt_penal_code_definitions
                WHERE category_id = ?
                    AND code = ?
                LIMIT 1
            `,
            [categoryId, code]
        )

        if (existingRows.length) {
            return res.status(409).json({ error: "A definition with that code already exists under this title" })
        }

        await pool.query(
            `
                INSERT INTO mdt_penal_code_definitions (category_id, code, name, definition)
                VALUES (?, ?, ?, ?)
            `,
            [categoryId, code, name, definition]
        )

        await logAction({
            actor: req.user,
            action: "CHARGE_DEFINITION_CREATED",
            targetType: "charge_definition",
            targetId: code,
            metadata: {
                title: categoryRows[0].name,
                name
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/definitions/:definitionId", auth, requirePermission("charges.edit"), async (req, res) => {
    try {
        const definitionId = Number.parseInt(req.params.definitionId, 10)
        const code = String(req.body?.code || "").trim()
        const name = String(req.body?.name || "").trim()
        const definition = String(req.body?.definition || "").trim()

        if (!Number.isInteger(definitionId) || definitionId <= 0) {
            return res.status(400).json({ error: "Definition ID is required" })
        }

        if (!code || !name || !definition) {
            return res.status(400).json({ error: "Code, name, and definition are required" })
        }

        const [definitionRows] = await pool.query(
            `
                SELECT id, category_id, code, name, definition
                FROM mdt_penal_code_definitions
                WHERE id = ?
                LIMIT 1
            `,
            [definitionId]
        )

        if (!definitionRows.length) {
            return res.status(404).json({ error: "Definition not found" })
        }

        const existingDefinition = definitionRows[0]
        const [existingRows] = await pool.query(
            `
                SELECT id
                FROM mdt_penal_code_definitions
                WHERE category_id = ?
                    AND code = ?
                    AND id != ?
                LIMIT 1
            `,
            [existingDefinition.category_id, code, definitionId]
        )

        if (existingRows.length) {
            return res.status(409).json({ error: "A definition with that code already exists under this title" })
        }

        await pool.query(
            `
                UPDATE mdt_penal_code_definitions
                SET code = ?, name = ?, definition = ?
                WHERE id = ?
            `,
            [code, name, definition, definitionId]
        )

        await logAction({
            actor: req.user,
            action: "CHARGE_DEFINITION_UPDATED",
            targetType: "charge_definition",
            targetId: String(definitionId),
            metadata: {
                previousCode: existingDefinition.code,
                nextCode: code,
                previousName: existingDefinition.name,
                nextName: name
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/categories/:categoryId", auth, requireRole(["superadmin"]), async (req, res) => {
    try {
        const categoryId = Number.parseInt(req.params.categoryId, 10)
        if (!Number.isInteger(categoryId) || categoryId <= 0) {
            return res.status(400).json({ error: "Category ID is required" })
        }

        const [categoryRows] = await pool.query(
            `
                SELECT id, name, kind
                FROM mdt_penal_code_categories
                WHERE id = ?
                LIMIT 1
            `,
            [categoryId]
        )

        if (!categoryRows.length) {
            return res.status(404).json({ error: "Category not found" })
        }

        const category = categoryRows[0]
        const [countRows] = await pool.query(
            `
                SELECT COUNT(*) AS total
                FROM mdt_penal_code_charges
                WHERE category = ?
            `,
            [category.name]
        )

        const total = Number(countRows[0]?.total || 0)
        if (total > 0) {
            return res.status(409).json({ error: "Cannot delete a category that still contains charges" })
        }

        await pool.query(
            "DELETE FROM mdt_penal_code_categories WHERE id = ?",
            [categoryId]
        )

        await logAction({
            actor: req.user,
            action: "CHARGE_CATEGORY_DELETED",
            targetType: "charge_category",
            targetId: category.name,
            metadata: { kind: category.kind }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.get("/:chargeId", auth, async (req, res) => {
    try {
        const chargeId = Number.parseInt(req.params.chargeId, 10)
        if (!Number.isInteger(chargeId) || chargeId <= 0) {
            return res.status(400).json({ error: "Charge ID is required" })
        }

        const [rows] = await pool.query(
            `
                SELECT id, title, code, category, class, fine, jail_time, points, description
                FROM mdt_penal_code_charges
                WHERE id = ?
                LIMIT 1
            `,
            [chargeId]
        )

        if (!rows.length) {
            return res.status(404).json({ error: "Charge not found" })
        }

        const [enhancementRows] = await pool.query(
            `
                SELECT id, charge_id, label, color, fine_percent_off, jail_percent_off, display_order
                FROM mdt_penal_code_charge_enhancements
                WHERE charge_id = ?
                ORDER BY display_order ASC, id ASC
            `,
            [chargeId]
        )

        res.json({
            charge: {
                ...rows[0],
                enhancements: enhancementRows
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.post("/", auth, requirePermission("charges.edit"), async (req, res) => {
    try {
        const title = String(req.body?.title || "").trim()
        const category = String(req.body?.category || "").trim()
        const enhancements = sanitizeEnhancements(req.body?.enhancements)

        if (!title) {
            return res.status(400).json({ error: "Title is required" })
        }

        if (category) {
            await ensureCategoryExists(category)
        }

        const [insertResult] = await pool.query(
            `
                INSERT INTO mdt_penal_code_charges (title, code, category, class, fine, jail_time, points, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
                title,
                String(req.body?.code || "").trim() || null,
                category || null,
                String(req.body?.class || "").trim() || null,
                Number(req.body?.fine || 0),
                Number(req.body?.jailTime || 0),
                Number(req.body?.points || 0),
                String(req.body?.description || "").trim() || null
            ]
        )

        const chargeId = insertResult.insertId
        if (chargeId) {
            await replaceChargeEnhancements(chargeId, enhancements)
        }

        await logAction({
            actor: req.user,
            action: "CHARGE_CREATED",
            targetType: "charge",
            targetId: title,
            metadata: {
                enhancementCount: enhancements.length
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.put("/:chargeId", auth, requirePermission("charges.edit"), async (req, res) => {
    try {
        const chargeId = Number.parseInt(req.params.chargeId, 10)
        const title = String(req.body?.title || "").trim()
        const category = String(req.body?.category || "").trim()
        const enhancements = sanitizeEnhancements(req.body?.enhancements)

        if (!Number.isInteger(chargeId) || chargeId <= 0) {
            return res.status(400).json({ error: "Charge ID is required" })
        }

        if (!title) {
            return res.status(400).json({ error: "Title is required" })
        }

        const [rows] = await pool.query(
            "SELECT id, title FROM mdt_penal_code_charges WHERE id = ? LIMIT 1",
            [chargeId]
        )

        if (!rows.length) {
            return res.status(404).json({ error: "Charge not found" })
        }

        if (category) {
            await ensureCategoryExists(category)
        }

        await pool.query(
            `
                UPDATE mdt_penal_code_charges
                SET title = ?, code = ?, category = ?, class = ?, fine = ?, jail_time = ?, points = ?, description = ?
                WHERE id = ?
            `,
            [
                title,
                String(req.body?.code || "").trim() || null,
                category || null,
                String(req.body?.class || "").trim() || null,
                Number(req.body?.fine || 0),
                Number(req.body?.jailTime || 0),
                Number(req.body?.points || 0),
                String(req.body?.description || "").trim() || null,
                chargeId
            ]
        )

        await replaceChargeEnhancements(chargeId, enhancements)

        await logAction({
            actor: req.user,
            action: "CHARGE_UPDATED",
            targetType: "charge",
            targetId: String(chargeId),
            metadata: {
                previousTitle: rows[0].title,
                nextTitle: title,
                category: category || null,
                enhancementCount: enhancements.length
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

router.delete("/:chargeId", auth, requireRole(["superadmin"]), async (req, res) => {
    try {
        const chargeId = Number.parseInt(req.params.chargeId, 10)
        if (!Number.isInteger(chargeId) || chargeId <= 0) {
            return res.status(400).json({ error: "Charge ID is required" })
        }

        const [rows] = await pool.query(
            "SELECT id, title FROM mdt_penal_code_charges WHERE id = ? LIMIT 1",
            [chargeId]
        )

        if (!rows.length) {
            return res.status(404).json({ error: "Charge not found" })
        }

        await pool.query(
            "DELETE FROM mdt_penal_code_charges WHERE id = ?",
            [chargeId]
        )
        await pool.query(
            "DELETE FROM mdt_penal_code_charge_enhancements WHERE charge_id = ?",
            [chargeId]
        )

        await logAction({
            actor: req.user,
            action: "CHARGE_DELETED",
            targetType: "charge",
            targetId: String(chargeId),
            metadata: {
                title: rows[0].title
            }
        })

        res.json({ success: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Server Error" })
    }
})

module.exports = router
