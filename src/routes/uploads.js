const express = require("express")
const auth = require("../middleware/auth")

const router = express.Router()

function getExtension(contentType) {
    switch (String(contentType || "").toLowerCase()) {
        case "image/jpeg":
            return "jpg"
        case "image/png":
            return "png"
        case "image/gif":
            return "gif"
        case "image/webp":
            return "webp"
        default:
            return "png"
    }
}

function normalizeFileName(fileName, contentType) {
    const fallback = `clipboard-${Date.now()}.${getExtension(contentType)}`
    const cleanName = String(fileName || fallback).replace(/[^a-zA-Z0-9._-]/g, "_")
    return cleanName.includes(".") ? cleanName : `${cleanName}.${getExtension(contentType)}`
}

router.post("/editor-image", auth, async (req, res) => {
    try {
        const uploadUrl = process.env.MDT_FILE_SERVER_UPLOAD_URL?.trim()
        const apiKey = process.env.MDT_FILE_SERVER_API_KEY?.trim()
        const data = String(req.body?.data || "")
        const contentType = String(req.body?.contentType || "image/png").trim()

        if (!uploadUrl || !apiKey) {
            return res.status(503).json({
                error: "File server upload is not configured",
                missingUploadUrl: !uploadUrl,
                missingApiKey: !apiKey
            })
        }

        if (!contentType.startsWith("image/")) {
            return res.status(400).json({ error: "Only image uploads are supported" })
        }

        if (!data) {
            return res.status(400).json({ error: "Image data is required" })
        }

        const buffer = Buffer.from(data, "base64")
        if (!buffer.length) {
            return res.status(400).json({ error: "Image data is invalid" })
        }

        const form = new FormData()
        const fileName = normalizeFileName(req.body?.fileName, contentType)
        form.append("file", new Blob([buffer], { type: contentType }), fileName)

        const response = await fetch(uploadUrl, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${apiKey}`
            },
            body: form
        })

        const responseText = await response.text()
        let payload = {}
        try {
            payload = responseText ? JSON.parse(responseText) : {}
        } catch (error) {
            payload = { message: responseText }
        }

        if (!response.ok) {
            return res.status(502).json({
                error: payload.error || payload.message || "File server upload failed",
                status: response.status
            })
        }

        if (!payload.url) {
            return res.status(502).json({ error: "File server response did not include a file URL" })
        }

        res.json({
            url: payload.url,
            path: payload.path,
            fileName: payload.fileName || fileName
        })
    } catch (error) {
        console.error("Failed to upload rich text image", error)
        res.status(502).json({ error: error.message || "Failed to upload image" })
    }
})

module.exports = router
