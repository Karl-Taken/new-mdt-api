const mariadb = require("mariadb")

function createMySqlPool({ host, port, user, password, database }) {
    const pool = mariadb.createPool({
        host,
        port,
        user,
        password,
        database,
        connectionLimit: 10,
        acquireTimeout: 10000
    })

    return {
        async query(sql, params = []) {
            const result = await pool.query(sql, params)
            return [Array.isArray(result) ? result : result]
        },
        async end() {
            return pool.end()
        }
    }
}

module.exports = createMySqlPool
