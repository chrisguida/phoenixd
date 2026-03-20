package fr.acinq.phoenixd.nwc

import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import kotlinx.serialization.Serializable

data class NwcConnection(
    val id: String,
    val label: String,
    val walletPrivateKey: PrivateKey,
    val clientPrivateKey: PrivateKey,
    val relayUrl: String,
    val budgetMsat: Long?, // null = unlimited
    val spentMsat: Long,
    val budgetIntervalSecs: Long?, // null = no refresh
    val lastBudgetResetAt: Long,
    val createdAt: Long,
) {
    val walletPubkey: PublicKey get() = walletPrivateKey.publicKey()
    val clientPubkey: PublicKey get() = clientPrivateKey.publicKey()

    /** Generate the nostr+walletconnect:// URI for the client (e.g. Alby Go) to scan. */
    fun toUri(): String {
        val walletPubkeyHex = walletPubkey.xOnly().value.toHex()
        val clientSecretHex = clientPrivateKey.value.toHex()
        return "nostr+walletconnect://${walletPubkeyHex}?relay=${relayUrl}&secret=${clientSecretHex}"
    }
}

/** Info returned to the user when creating a new NWC connection. */
@Serializable
data class NwcConnectionInfo(
    val id: String,
    val label: String,
    val uri: String,
    val walletPubkey: String,
    val relayUrl: String,
    val budgetMsat: Long?,
    val budgetIntervalSecs: Long?,
)

/** Summary of an NWC connection for listing/showing. */
@Serializable
data class NwcConnectionSummary(
    val id: String,
    val label: String,
    val uri: String,
    val walletPubkey: String,
    val relayUrl: String,
    val budgetMsat: Long?,
    val spentMsat: Long,
    val budgetIntervalSecs: Long?,
    val createdAt: Long,
)
