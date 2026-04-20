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

    function normalizeQueryResult(result) {
        return [Array.isArray(result) ? result : result]
    }

    return {
        async query(sql, params = []) {
            const result = await pool.query(sql, params)
            return normalizeQueryResult(result)
        },
        async getConnection() {
            const connection = await pool.getConnection()

            return {
                async query(sql, params = []) {
                    const result = await connection.query(sql, params)
                    return normalizeQueryResult(result)
                },
                async beginTransaction() {
                    return connection.beginTransaction()
                },
                async commit() {
                    return connection.commit()
                },
                async rollback() {
                    return connection.rollback()
                },
                release() {
                    connection.release()
                }
            }
        },
        async end() {
            return pool.end()
        }
    }
}

module.exports = createMySqlPool
