const axios = require("axios")
const pool = require("../config/db")

const SERVICE_NAME = "mdt-resource-api"
const CACHE_TTL_MS = 60 * 1000

let cachedKey = {
    value: null,
    expiresAt: 0
}

async function getApiKey() {
    const envValue = process.env.MDT_RESOURCE_API_KEY?.trim()
    if (envValue) {
        return envValue
    }

    if (cachedKey.value && cachedKey.expiresAt > Date.now()) {
        return cachedKey.value
    }

    const [rows] = await pool.query(
        `
            SELECT api_key
            FROM mdt_service_keys
            WHERE service_name = ?
                AND is_active = 1
            LIMIT 1
        `,
        [SERVICE_NAME]
    )

    cachedKey = {
        value: rows[0]?.api_key || null,
        expiresAt: Date.now() + CACHE_TTL_MS
    }

    return cachedKey.value
}

async function requestBridge(path, options = {}) {
    const baseUrl = process.env.MDT_RESOURCE_BASE_URL?.trim()
    if (!baseUrl) {
        return null
    }

    const apiKey = await getApiKey()
    if (!apiKey) {
        return null
    }

    return axios({
        method: options.method || "get",
        url: `${baseUrl}${path}`,
        timeout: 5000,
        headers: {
            Authorization: `Bearer ${apiKey}`
        }
    })
}

async function fetchOnlinePlayers() {
    try {
        const response = await requestBridge("/players")
        return Array.isArray(response?.data?.players) ? response.data.players : []
    } catch (error) {
        console.warn("MDT bridge player fetch failed", error.message || error)
        return []
    }
}

module.exports = {
    fetchOnlinePlayers
}
