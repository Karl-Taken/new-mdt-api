const DISCORD_API_BASE_URL = "https://discord.com/api/v10"

function getDiscordBotToken() {
    return String(process.env.DISCORD_BOT_TOKEN || "").trim()
}

async function discordRequest(path, options = {}) {
    const token = getDiscordBotToken()
    if (!token) {
        throw new Error("DISCORD_BOT_TOKEN is not configured")
    }

    const response = await fetch(`${DISCORD_API_BASE_URL}${path}`, {
        ...options,
        headers: {
            Authorization: `Bot ${token}`,
            "Content-Type": "application/json",
            ...(options.headers || {})
        }
    })

    if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Discord API request failed (${response.status}): ${errorText}`)
    }

    return response.json()
}

async function sendDirectMessage(discordId, content) {
    const channel = await discordRequest("/users/@me/channels", {
        method: "POST",
        body: JSON.stringify({
            recipient_id: discordId
        })
    })

    await discordRequest(`/channels/${channel.id}/messages`, {
        method: "POST",
        body: JSON.stringify({
            content
        })
    })
}

module.exports = {
    sendDirectMessage
}
