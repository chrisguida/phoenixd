package fr.acinq.phoenixd.nwc

import app.cash.sqldelight.db.SqlDriver
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.NodeParams
import fr.acinq.lightning.PaymentEvents
import fr.acinq.lightning.channel.states.ChannelStateWithCommitments
import fr.acinq.lightning.channel.states.Closed
import fr.acinq.lightning.channel.states.Closing
import fr.acinq.lightning.db.LightningIncomingPayment
import fr.acinq.lightning.db.LightningOutgoingPayment
import fr.acinq.lightning.io.PaymentNotSent
import fr.acinq.lightning.io.PaymentSent
import fr.acinq.lightning.io.Peer
import fr.acinq.lightning.logging.LoggerFactory
import fr.acinq.lightning.logging.debug
import fr.acinq.lightning.logging.info
import fr.acinq.lightning.logging.warning
import fr.acinq.lightning.payment.Bolt11Invoice
import fr.acinq.lightning.utils.currentTimestampMillis
import fr.acinq.lightning.utils.currentTimestampSeconds
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.sum
import fr.acinq.phoenixd.BuildVersions
import fr.acinq.phoenixd.db.SqlitePaymentsDb
import io.ktor.client.*
import io.ktor.client.plugins.websocket.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.json.*
import kotlin.time.Duration.Companion.seconds

class NwcService(
    private val nodeParams: NodeParams,
    private val peer: Peer,
    private val relayUrl: String,
    private val driver: SqlDriver,
    private val loggerFactory: LoggerFactory,
) {
    private val log = loggerFactory.newLogger(this::class)
    private val db = NwcDb(driver)
    private val relays = mutableMapOf<String, NostrRelay>() // connectionId -> relay
    private val json = Json { ignoreUnknownKeys = true }
    private val processedEventIds = LinkedHashSet<String>() // dedup cache
    private val maxProcessedEvents = 1000

    fun start(scope: CoroutineScope) {
        db.init()
        log.info { "NWC service starting, relay=$relayUrl" }

        // Start relay connections for all saved NWC connections
        val connections = db.getAll()
        log.info { "loaded ${connections.size} NWC connection(s)" }
        for (conn in connections) {
            startConnection(scope, conn)
        }

        // Watch for payment events to send notifications
        scope.launch {
            nodeParams.nodeEvents
                .filterIsInstance<PaymentEvents>()
                .collect { event ->
                    when (event) {
                        is PaymentEvents.PaymentReceived -> {
                            val payment = event.payment
                            if (payment is LightningIncomingPayment) {
                                sendPaymentNotification("payment_received", buildJsonObject {
                                    put("type", "incoming")
                                    val inv = (payment as? fr.acinq.lightning.db.Bolt11IncomingPayment)?.paymentRequest
                                    put("invoice", inv?.write() ?: "")
                                    put("description", inv?.description ?: "")
                                    put("description_hash", "")
                                    put("preimage", payment.paymentPreimage.toHex())
                                    put("payment_hash", payment.paymentHash.toHex())
                                    put("amount", payment.amount.toLong())
                                    put("fees_paid", payment.fees.toLong())
                                    put("created_at", payment.createdAt / 1000)
                                    put("settled_at", payment.completedAt?.let { it / 1000 })
                                    putJsonObject("metadata") {}
                                })
                            }
                        }
                        is PaymentEvents.PaymentSent -> {
                            val payment = event.payment
                            if (payment is LightningOutgoingPayment) {
                                sendPaymentNotification("payment_sent", buildJsonObject {
                                    put("type", "outgoing")
                                    val details = payment.details
                                    if (details is LightningOutgoingPayment.Details.Normal) {
                                        put("invoice", details.paymentRequest.write())
                                        put("description", details.paymentRequest.description ?: "")
                                    } else {
                                        put("invoice", "")
                                        put("description", "")
                                    }
                                    put("description_hash", "")
                                    put("preimage", (payment.status as? LightningOutgoingPayment.Status.Succeeded)?.preimage?.toHex() ?: "")
                                    put("payment_hash", payment.paymentHash.toHex())
                                    put("amount", payment.recipientAmount.toLong())
                                    put("fees_paid", payment.routingFee.toLong())
                                    put("created_at", payment.createdAt / 1000)
                                    put("settled_at", (payment.status as? LightningOutgoingPayment.Status.Succeeded)?.completedAt?.let { it / 1000 })
                                    putJsonObject("metadata") {}
                                })
                            }
                        }
                    }
                }
        }
    }

    fun createConnection(
        scope: CoroutineScope,
        label: String,
        budgetMsat: Long? = null,
        budgetIntervalSecs: Long? = null,
    ): NwcConnectionInfo {
        val walletKey = PrivateKey(randomBytes32())
        val clientKey = PrivateKey(randomBytes32())
        val id = randomBytes32().toHex().take(16)
        val now = currentTimestampMillis()

        val conn = NwcConnection(
            id = id,
            label = label,
            walletPrivateKey = walletKey,
            clientPrivateKey = clientKey,
            relayUrl = relayUrl,
            budgetMsat = budgetMsat,
            spentMsat = 0,
            budgetIntervalSecs = budgetIntervalSecs,
            lastBudgetResetAt = now,
            createdAt = now,
        )

        db.insert(conn)
        startConnection(scope, conn)

        return NwcConnectionInfo(
            id = id,
            label = label,
            uri = conn.toUri(),
            walletPubkey = walletKey.publicKey().xOnly().value.toHex(),
            relayUrl = relayUrl,
            budgetMsat = budgetMsat,
            budgetIntervalSecs = budgetIntervalSecs,
        )
    }

    fun listConnections(): List<NwcConnectionSummary> {
        return db.getAll().map { it.toSummary() }
    }

    fun getConnection(id: String): NwcConnectionSummary? {
        return db.getById(id)?.toSummary()
    }

    fun revokeConnection(id: String): Boolean {
        val relay = relays.remove(id)
        relay?.stop()
        val conn = db.getById(id) ?: return false
        db.delete(id)
        return true
    }

    private fun NwcConnection.toSummary() = NwcConnectionSummary(
        id = id,
        label = label,
        uri = toUri(),
        walletPubkey = walletPubkey.xOnly().value.toHex(),
        relayUrl = relayUrl,
        budgetMsat = budgetMsat,
        spentMsat = spentMsat,
        budgetIntervalSecs = budgetIntervalSecs,
        createdAt = createdAt,
    )

    // -- Connection Lifecycle --

    private fun startConnection(scope: CoroutineScope, conn: NwcConnection) {
        val client = HttpClient {
            install(WebSockets)
        }
        val relay = NostrRelay(conn.relayUrl, loggerFactory)
        relays[conn.id] = relay
        relay.start(scope, client)

        // Wait for connection, then publish info event and subscribe
        scope.launch {
            relay.connected.first { it }
            publishInfoEvent(relay, conn)
            subscribeToRequests(relay, conn)
        }

        // Handle incoming NIP-47 requests
        scope.launch {
            relay.messages.collect { msg ->
                when (msg) {
                    is RelayMessage.Event -> {
                        val eventId = msg.event.id.toHex()
                        // Check expiration tag
                        val expiration = msg.event.getTagValue("expiration")?.toLongOrNull()
                        if (expiration != null && expiration < currentTimestampSeconds()) {
                            log.debug { "ignoring expired NWC event $eventId" }
                        } else if (msg.event.kind == Nip47Kinds.REQUEST && processedEventIds.add(eventId)) {
                            // Evict oldest entries if cache is full
                            while (processedEventIds.size > maxProcessedEvents) {
                                processedEventIds.remove(processedEventIds.first())
                            }
                            handleNip47Request(relay, conn, msg.event)
                        }
                    }
                    is RelayMessage.Eose -> {
                        log.debug { "EOSE for subscription ${msg.subscriptionId}" }
                    }
                    is RelayMessage.Ok -> {
                        if (!msg.accepted) {
                            log.warning { "relay rejected event ${msg.eventId}: ${msg.message}" }
                        }
                    }
                    is RelayMessage.Notice -> {
                        log.info { "relay notice: ${msg.message}" }
                    }
                    is RelayMessage.Closed -> {
                        log.info { "subscription closed: ${msg.subscriptionId} ${msg.message}" }
                    }
                }
            }
        }

        // Auto-reconnect: re-publish info event and re-subscribe when reconnected
        scope.launch {
            relay.connected
                .drop(1) // skip initial
                .filter { it }
                .collect {
                    log.info { "relay reconnected, re-publishing info event for ${conn.label}" }
                    publishInfoEvent(relay, conn)
                    subscribeToRequests(relay, conn)
                }
        }
    }

    private suspend fun publishInfoEvent(relay: NostrRelay, conn: NwcConnection) {
        val capabilities = Nip47Methods.ALL.joinToString(" ")
        val tags = listOf(
            listOf("encryption", "nip44_v2", "nip04"),
            listOf("notifications", "payment_received payment_sent"),
        )
        val event = NostrCrypto.signEvent(
            privateKey = conn.walletPrivateKey,
            createdAt = currentTimestampSeconds(),
            kind = Nip47Kinds.INFO,
            tags = tags,
            content = capabilities,
        )
        relay.sendEvent(event)
    }

    private suspend fun subscribeToRequests(relay: NostrRelay, conn: NwcConnection) {
        val walletPubkeyHex = conn.walletPubkey.xOnly().value.toHex()
        val clientPubkeyHex = conn.clientPubkey.xOnly().value.toHex()
        val filter = NostrFilter(
            kinds = listOf(Nip47Kinds.REQUEST),
            authors = listOf(clientPubkeyHex),
            tags = mapOf("p" to listOf(walletPubkeyHex)),
            since = currentTimestampSeconds() - 60,
        )
        relay.subscribe("nwc-${conn.id}", filter)
    }

    // -- NIP-47 Request Handling --

    private suspend fun handleNip47Request(relay: NostrRelay, conn: NwcConnection, event: NostrEvent) {
        try {
            // Try NIP-44 first, fall back to NIP-04
            val (decrypted, useNip44) = decryptRequest(conn, event.content)
            log.debug { "NWC request (nip44=$useNip44): $decrypted" }

            val request = json.decodeFromString<Nip47Request>(decrypted)
            val response = processRequest(conn, request)

            val responseJson = json.encodeToString(Nip47Response.serializer(), response)
            // Respond with the same encryption method the client used
            val encrypted = if (useNip44) {
                val conversationKey = NostrCrypto.nip44ConversationKey(conn.walletPrivateKey, conn.clientPubkey)
                NostrCrypto.nip44Encrypt(conversationKey, responseJson)
            } else {
                val sharedSecret = NostrCrypto.nip04SharedSecret(conn.walletPrivateKey, conn.clientPubkey)
                NostrCrypto.nip04Encrypt(sharedSecret, responseJson)
            }

            val tags = listOf(
                listOf("p", event.pubkey.toHex()),
                listOf("e", event.id.toHex()),
            )
            val responseEvent = NostrCrypto.signEvent(
                privateKey = conn.walletPrivateKey,
                createdAt = currentTimestampSeconds(),
                kind = Nip47Kinds.RESPONSE,
                tags = tags,
                content = encrypted,
            )
            relay.sendEvent(responseEvent)
        } catch (e: Exception) {
            log.warning { "failed to handle NWC request: ${e.message}" }
        }
    }

    /** Try NIP-44 decryption first, fall back to NIP-04. Returns (plaintext, usedNip44). */
    private fun decryptRequest(conn: NwcConnection, content: String): Pair<String, Boolean> {
        return try {
            val conversationKey = NostrCrypto.nip44ConversationKey(conn.walletPrivateKey, conn.clientPubkey)
            Pair(NostrCrypto.nip44Decrypt(conversationKey, content), true)
        } catch (e: Exception) {
            log.debug { "NIP-44 decrypt failed, trying NIP-04: ${e.message}" }
            val sharedSecret = NostrCrypto.nip04SharedSecret(conn.walletPrivateKey, conn.clientPubkey)
            Pair(NostrCrypto.nip04Decrypt(sharedSecret, content), false)
        }
    }

    private suspend fun processRequest(conn: NwcConnection, request: Nip47Request): Nip47Response {
        return try {
            when (request.method) {
                Nip47Methods.GET_INFO -> handleGetInfo()
                Nip47Methods.GET_BALANCE -> handleGetBalance()
                Nip47Methods.MAKE_INVOICE -> handleMakeInvoice(request.params)
                Nip47Methods.PAY_INVOICE -> handlePayInvoice(conn, request.params)
                Nip47Methods.LOOKUP_INVOICE -> handleLookupInvoice(request.params)
                Nip47Methods.LIST_TRANSACTIONS -> handleListTransactions(request.params)
                else -> Nip47Response(
                    resultType = request.method,
                    error = Nip47Error(Nip47Error.NOT_IMPLEMENTED, "method not supported: ${request.method}")
                )
            }
        } catch (e: Exception) {
            log.warning { "error processing NWC ${request.method}: ${e.message}" }
            Nip47Response(
                resultType = request.method,
                error = Nip47Error(Nip47Error.INTERNAL, e.message ?: "internal error")
            )
        }
    }

    private fun handleGetInfo(): Nip47Response {
        val result = buildJsonObject {
            put("alias", "phoenixd")
            put("color", "000000")
            put("pubkey", nodeParams.nodeId.toHex())
            put("network", nodeParams.chain.name.lowercase())
            put("block_height", peer.currentTipFlow.value)
            putJsonArray("block_hash") {}
            putJsonArray("methods") {
                Nip47Methods.ALL.forEach { add(it) }
            }
            putJsonArray("notifications") {
                add("payment_received")
                add("payment_sent")
            }
        }
        return Nip47Response(resultType = Nip47Methods.GET_INFO, result = result)
    }

    private fun handleGetBalance(): Nip47Response {
        val balanceMsat = peer.channels.values
            .filterIsInstance<ChannelStateWithCommitments>()
            .filterNot { it is Closing || it is Closed }
            .map { it.commitments.active.first().availableBalanceForSend(it.commitments.channelParams, it.commitments.changes) }
            .sum().toLong()

        val result = buildJsonObject {
            put("balance", balanceMsat)
        }
        return Nip47Response(resultType = Nip47Methods.GET_BALANCE, result = result)
    }

    private suspend fun handleMakeInvoice(params: JsonObject): Nip47Response {
        val amountMsat = params["amount"]?.jsonPrimitive?.longOrNull
        val description = params["description"]?.jsonPrimitive?.contentOrNull ?: ""
        val expiry = params["expiry"]?.jsonPrimitive?.longOrNull

        val invoice = peer.createInvoice(
            randomBytes32(),
            amountMsat?.msat,
            Either.Left(description),
            expiry?.seconds
        )

        val result = buildJsonObject {
            put("type", "incoming")
            put("invoice", invoice.write())
            put("description", description)
            put("description_hash", "")
            put("preimage", "")
            put("payment_hash", invoice.paymentHash.toHex())
            put("amount", amountMsat ?: 0L)
            put("fees_paid", 0L)
            put("created_at", currentTimestampSeconds())
            put("expires_at", currentTimestampSeconds() + (expiry ?: 3600))
            putJsonObject("metadata") {}
        }
        return Nip47Response(resultType = Nip47Methods.MAKE_INVOICE, result = result)
    }

    private suspend fun handlePayInvoice(conn: NwcConnection, params: JsonObject): Nip47Response {
        val bolt11 = params["invoice"]?.jsonPrimitive?.contentOrNull
            ?: return Nip47Response(
                resultType = Nip47Methods.PAY_INVOICE,
                error = Nip47Error(Nip47Error.OTHER, "missing invoice parameter")
            )

        val invoice = try { Bolt11Invoice.read(bolt11).get() } catch (_: Exception) {
            return Nip47Response(
                resultType = Nip47Methods.PAY_INVOICE,
                error = Nip47Error(Nip47Error.OTHER, "invalid bolt11 invoice")
            )
        }

        val amountMsat = params["amount"]?.jsonPrimitive?.longOrNull?.msat ?: invoice.amount
            ?: return Nip47Response(
                resultType = Nip47Methods.PAY_INVOICE,
                error = Nip47Error(Nip47Error.OTHER, "invoice has no amount and no amount provided")
            )

        // Budget check
        val freshConn = db.getById(conn.id)
        if (freshConn != null && freshConn.budgetMsat != null) {
            // Check if budget needs reset
            if (freshConn.budgetIntervalSecs != null) {
                val now = currentTimestampMillis()
                val elapsed = now - freshConn.lastBudgetResetAt
                if (elapsed >= freshConn.budgetIntervalSecs * 1000) {
                    db.resetBudget(conn.id, now)
                }
            }
            val currentSpent = db.getById(conn.id)?.spentMsat ?: 0
            if (currentSpent + amountMsat.toLong() > freshConn.budgetMsat) {
                return Nip47Response(
                    resultType = Nip47Methods.PAY_INVOICE,
                    error = Nip47Error(Nip47Error.QUOTA_EXCEEDED, "budget exceeded")
                )
            }
        }

        when (val event = peer.payInvoice(amountMsat, invoice)) {
            is PaymentSent -> {
                // Update spent budget
                val currentSpent = db.getById(conn.id)?.spentMsat ?: 0
                db.updateSpent(conn.id, currentSpent + amountMsat.toLong())

                val result = buildJsonObject {
                    put("preimage", (event.payment.status as LightningOutgoingPayment.Status.Succeeded).preimage.toHex())
                }
                return Nip47Response(resultType = Nip47Methods.PAY_INVOICE, result = result)
            }
            is PaymentNotSent -> {
                return Nip47Response(
                    resultType = Nip47Methods.PAY_INVOICE,
                    error = Nip47Error(Nip47Error.PAYMENT_FAILED, "payment failed: ${event.reason}")
                )
            }
            else -> {
                return Nip47Response(
                    resultType = Nip47Methods.PAY_INVOICE,
                    error = Nip47Error(Nip47Error.INTERNAL, "unexpected payment result")
                )
            }
        }
    }

    private suspend fun handleLookupInvoice(params: JsonObject): Nip47Response {
        val paymentHash = params["payment_hash"]?.jsonPrimitive?.contentOrNull
        val bolt11 = params["invoice"]?.jsonPrimitive?.contentOrNull

        val hash = when {
            paymentHash != null -> ByteVector32.fromValidHex(paymentHash)
            bolt11 != null -> try { Bolt11Invoice.read(bolt11).get().paymentHash } catch (_: Exception) { null }
            else -> null
        } ?: return Nip47Response(
            resultType = Nip47Methods.LOOKUP_INVOICE,
            error = Nip47Error(Nip47Error.OTHER, "provide payment_hash or invoice")
        )

        val paymentsDb = peer.db.payments as SqlitePaymentsDb
        val payment = paymentsDb.getIncomingPayment(hash)

        if (payment == null) {
            return Nip47Response(
                resultType = Nip47Methods.LOOKUP_INVOICE,
                error = Nip47Error(Nip47Error.NOT_FOUND, "payment not found")
            )
        }

        val lightningPayment = payment as? LightningIncomingPayment
        val result = buildJsonObject {
            put("type", "incoming")
            val inv = (payment as? fr.acinq.lightning.db.Bolt11IncomingPayment)?.paymentRequest
            put("invoice", inv?.write() ?: "")
            put("description", inv?.description ?: "")
            put("description_hash", "")
            put("preimage", lightningPayment?.paymentPreimage?.toHex() ?: "")
            put("payment_hash", hash.toHex())
            put("amount", payment.amount.toLong())
            put("fees_paid", payment.fees.toLong())
            put("created_at", payment.createdAt / 1000)
            put("settled_at", payment.completedAt?.let { it / 1000 })
            putJsonObject("metadata") {}
        }
        return Nip47Response(resultType = Nip47Methods.LOOKUP_INVOICE, result = result)
    }

    private suspend fun handleListTransactions(params: JsonObject): Nip47Response {
        val from = params["from"]?.jsonPrimitive?.longOrNull
        val until = params["until"]?.jsonPrimitive?.longOrNull
        val limit = params["limit"]?.jsonPrimitive?.intOrNull ?: 20
        val offset = params["offset"]?.jsonPrimitive?.intOrNull ?: 0
        val unpaid = params["unpaid"]?.jsonPrimitive?.booleanOrNull ?: false
        val type = params["type"]?.jsonPrimitive?.contentOrNull

        val paymentsDb = peer.db.payments as SqlitePaymentsDb
        val transactions = buildJsonArray {
            // Incoming payments
            if (type == null || type == "incoming") {
                val incoming = paymentsDb.listIncomingPayments(
                    from = (from ?: 0) * 1000,
                    to = (until ?: currentTimestampSeconds()) * 1000,
                    limit = limit.toLong(),
                    offset = offset.toLong(),
                    listAll = unpaid,
                )
                for ((payment, _) in incoming) {
                    if (payment is LightningIncomingPayment) {
                        addJsonObject {
                            put("type", "incoming")
                            val inv = (payment as? fr.acinq.lightning.db.Bolt11IncomingPayment)?.paymentRequest
                            put("invoice", inv?.write() ?: "")
                            put("description", inv?.description ?: "")
                            put("description_hash", "")
                            put("preimage", payment.paymentPreimage.toHex())
                            put("payment_hash", payment.paymentHash.toHex())
                            put("amount", payment.amount.toLong())
                            put("fees_paid", payment.fees.toLong())
                            put("created_at", payment.createdAt / 1000)
                            put("settled_at", payment.completedAt?.let { it / 1000 })
                            putJsonObject("metadata") {}
                        }
                    }
                }
            }

            // Outgoing payments
            if (type == null || type == "outgoing") {
                val outgoing = paymentsDb.listOutgoingPayments(
                    from = (from ?: 0) * 1000,
                    to = (until ?: currentTimestampSeconds()) * 1000,
                    limit = limit.toLong(),
                    offset = offset.toLong(),
                    listAll = unpaid,
                )
                for (payment in outgoing) {
                    if (payment is LightningOutgoingPayment) {
                        addJsonObject {
                            put("type", "outgoing")
                            val details = payment.details
                            if (details is LightningOutgoingPayment.Details.Normal) {
                                put("invoice", details.paymentRequest.write())
                                put("description", details.paymentRequest.description ?: "")
                            } else {
                                put("invoice", "")
                                put("description", "")
                            }
                            put("description_hash", "")
                            put("preimage", (payment.status as? LightningOutgoingPayment.Status.Succeeded)?.preimage?.toHex() ?: "")
                            put("payment_hash", payment.paymentHash.toHex())
                            put("amount", payment.recipientAmount.toLong())
                            put("fees_paid", payment.routingFee.toLong())
                            put("created_at", payment.createdAt / 1000)
                            put("settled_at", (payment.status as? LightningOutgoingPayment.Status.Succeeded)?.completedAt?.let { it / 1000 })
                            putJsonObject("metadata") {}
                        }
                    }
                }
            }
        }

        val result = buildJsonObject {
            put("transactions", transactions)
        }
        return Nip47Response(resultType = Nip47Methods.LIST_TRANSACTIONS, result = result)
    }

    // -- Notifications --

    private suspend fun sendPaymentNotification(notificationType: String, paymentData: JsonObject) {
        for ((connId, relay) in relays) {
            val conn = db.getById(connId) ?: continue
            try {
                val notification = Nip47Notification(
                    notificationType = notificationType,
                    notification = paymentData,
                )
                val notifJson = json.encodeToString(Nip47Notification.serializer(), notification)
                val clientPubkeyHex = conn.clientPubkey.xOnly().value.toHex()
                val tags = listOf(listOf("p", clientPubkeyHex))
                val now = currentTimestampSeconds()

                // Send NIP-44 notification (kind 23197)
                try {
                    val conversationKey = NostrCrypto.nip44ConversationKey(conn.walletPrivateKey, conn.clientPubkey)
                    val nip44Event = NostrCrypto.signEvent(
                        privateKey = conn.walletPrivateKey,
                        createdAt = now,
                        kind = Nip47Kinds.NOTIFICATION_NIP44,
                        tags = tags,
                        content = NostrCrypto.nip44Encrypt(conversationKey, notifJson),
                    )
                    relay.sendEvent(nip44Event)
                } catch (e: Exception) {
                    log.warning { "failed to send NIP-44 notification for ${conn.label}: ${e.message}" }
                }

                // Send NIP-04 notification (kind 23196)
                try {
                    val sharedSecret = NostrCrypto.nip04SharedSecret(conn.walletPrivateKey, conn.clientPubkey)
                    val nip04Event = NostrCrypto.signEvent(
                        privateKey = conn.walletPrivateKey,
                        createdAt = now,
                        kind = Nip47Kinds.NOTIFICATION_NIP04,
                        tags = tags,
                        content = NostrCrypto.nip04Encrypt(sharedSecret, notifJson),
                    )
                    relay.sendEvent(nip04Event)
                } catch (e: Exception) {
                    log.warning { "failed to send NIP-04 notification for ${conn.label}: ${e.message}" }
                }

                log.info { "sent $notificationType notification for connection ${conn.label}" }
            } catch (e: Exception) {
                log.warning { "failed to send notification for connection ${conn.label}: ${e.message}" }
            }
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
