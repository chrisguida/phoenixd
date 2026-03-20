package fr.acinq.phoenixd.nwc

import fr.acinq.lightning.logging.LoggerFactory
import fr.acinq.lightning.logging.debug
import fr.acinq.lightning.logging.info
import fr.acinq.lightning.logging.warning
import io.ktor.client.*
import io.ktor.client.plugins.websocket.*
import io.ktor.websocket.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlin.time.Duration.Companion.seconds

class NostrRelay(
    private val url: String,
    private val loggerFactory: LoggerFactory,
) {
    private val log = loggerFactory.newLogger(this::class)
    private val _events = MutableSharedFlow<RelayMessage>()
    val messages: SharedFlow<RelayMessage> = _events.asSharedFlow()

    private var session: DefaultWebSocketSession? = null
    private var connectJob: Job? = null

    val connected: StateFlow<Boolean> get() = _connected.asStateFlow()
    private val _connected = MutableStateFlow(false)

    fun start(scope: CoroutineScope, client: HttpClient) {
        connectJob = scope.launch {
            while (isActive) {
                try {
                    log.info { "connecting to relay: $url" }
                    client.webSocket(url) {
                        session = this
                        _connected.value = true
                        log.info { "connected to relay: $url" }
                        try {
                            for (frame in incoming) {
                                when (frame) {
                                    is Frame.Text -> {
                                        val text = frame.readText()
                                        log.debug { "relay recv: $text" }
                                        try {
                                            val msg = RelayMessage.parse(text)
                                            if (msg != null) _events.emit(msg)
                                        } catch (e: Exception) {
                                            log.warning { "failed to parse relay message: ${e.message}" }
                                        }
                                    }
                                    else -> {}
                                }
                            }
                        } finally {
                            session = null
                            _connected.value = false
                        }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    log.warning { "relay connection error: ${e.message}" }
                }
                _connected.value = false
                session = null
                log.info { "relay disconnected, reconnecting in 5s..." }
                delay(5.seconds)
            }
        }
    }

    suspend fun send(text: String) {
        val s = session
        if (s != null) {
            log.debug { "relay send: $text" }
            s.send(Frame.Text(text))
        } else {
            log.warning { "cannot send, not connected to relay" }
        }
    }

    suspend fun sendEvent(event: NostrEvent) {
        send(ClientMessage.event(event))
    }

    suspend fun subscribe(subscriptionId: String, filter: NostrFilter) {
        send(ClientMessage.req(subscriptionId, filter))
    }

    suspend fun unsubscribe(subscriptionId: String) {
        send(ClientMessage.close(subscriptionId))
    }

    fun stop() {
        connectJob?.cancel()
        connectJob = null
        session = null
        _connected.value = false
    }
}
