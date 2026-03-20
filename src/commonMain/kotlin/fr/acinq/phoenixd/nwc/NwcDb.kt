package fr.acinq.phoenixd.nwc

import app.cash.sqldelight.db.SqlDriver
import fr.acinq.bitcoin.PrivateKey

class NwcDb(private val driver: SqlDriver) {

    fun init() {
        driver.execute(null, """
            CREATE TABLE IF NOT EXISTS nwc_connections (
                id TEXT NOT NULL PRIMARY KEY,
                label TEXT NOT NULL,
                wallet_private_key TEXT NOT NULL,
                client_private_key TEXT NOT NULL,
                relay_url TEXT NOT NULL,
                budget_msat INTEGER,
                spent_msat INTEGER NOT NULL DEFAULT 0,
                budget_interval_secs INTEGER,
                last_budget_reset_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
        """.trimIndent(), 0)
    }

    fun insert(conn: NwcConnection) {
        driver.execute(null, """
            INSERT INTO nwc_connections (
                id, label, wallet_private_key, client_private_key, relay_url,
                budget_msat, spent_msat, budget_interval_secs, last_budget_reset_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent(), 10) {
            bindString(0, conn.id)
            bindString(1, conn.label)
            bindString(2, conn.walletPrivateKey.value.toHex())
            bindString(3, conn.clientPrivateKey.value.toHex())
            bindString(4, conn.relayUrl)
            if (conn.budgetMsat != null) bindLong(5, conn.budgetMsat) else bindString(5, null)
            bindLong(6, conn.spentMsat)
            if (conn.budgetIntervalSecs != null) bindLong(7, conn.budgetIntervalSecs) else bindString(7, null)
            bindLong(8, conn.lastBudgetResetAt)
            bindLong(9, conn.createdAt)
        }
    }

    fun getAll(): List<NwcConnection> {
        val result = mutableListOf<NwcConnection>()
        driver.executeQuery(null, "SELECT * FROM nwc_connections", mapper = { cursor ->
            while (cursor.next().value) {
                result.add(cursorToConnection(cursor))
            }
            app.cash.sqldelight.db.QueryResult.Value(result)
        }, 0)
        return result
    }

    fun getById(id: String): NwcConnection? {
        var result: NwcConnection? = null
        driver.executeQuery(null, "SELECT * FROM nwc_connections WHERE id = ?", mapper = { cursor ->
            if (cursor.next().value) {
                result = cursorToConnection(cursor)
            }
            app.cash.sqldelight.db.QueryResult.Value(result)
        }, 1) {
            bindString(0, id)
        }
        return result
    }

    fun updateSpent(id: String, spentMsat: Long) {
        driver.execute(null, "UPDATE nwc_connections SET spent_msat = ? WHERE id = ?", 2) {
            bindLong(0, spentMsat)
            bindString(1, id)
        }
    }

    fun resetBudget(id: String, now: Long) {
        driver.execute(null, "UPDATE nwc_connections SET spent_msat = 0, last_budget_reset_at = ? WHERE id = ?", 2) {
            bindLong(0, now)
            bindString(1, id)
        }
    }

    fun delete(id: String) {
        driver.execute(null, "DELETE FROM nwc_connections WHERE id = ?", 1) {
            bindString(0, id)
        }
    }

    private fun cursorToConnection(cursor: app.cash.sqldelight.db.SqlCursor): NwcConnection {
        return NwcConnection(
            id = cursor.getString(0)!!,
            label = cursor.getString(1)!!,
            walletPrivateKey = PrivateKey.fromHex(cursor.getString(2)!!),
            clientPrivateKey = PrivateKey.fromHex(cursor.getString(3)!!),
            relayUrl = cursor.getString(4)!!,
            budgetMsat = cursor.getLong(5),
            spentMsat = cursor.getLong(6) ?: 0,
            budgetIntervalSecs = cursor.getLong(7),
            lastBudgetResetAt = cursor.getLong(8) ?: 0,
            createdAt = cursor.getLong(9) ?: 0,
        )
    }
}
