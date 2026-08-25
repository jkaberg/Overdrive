package com.overdrive.app.overlink

import com.overdrive.app.util.DaemonHttpClient
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * App-side client for the daemon's `/api/overlink/v1` endpoints.
 *
 * The pairing state machine, the Tailscale API credentials and the device
 * registry all live in the daemon JVM ([OverlinkPairingManager] explains why),
 * so the settings screen reaches them the same way every other cross-UID read in
 * this app does: authenticated loopback HTTP via [DaemonHttpClient].
 *
 * Every method here is **blocking** and must be called off the UI thread. A key
 * mint is up to three round trips to `api.tailscale.com` over what may be a car
 * SIM; a settings screen frozen for four seconds reads as a crash and gets
 * reported as one.
 *
 * Nothing throws. Failures come back as [Result.failure] with a message the
 * pairing screen can show verbatim, because each of the daemon's failure
 * reasons already maps to its own user-facing action.
 */
object OverlinkClient {

    private const val BASE = "/api/overlink/v1"

    /** Generous: a mint is three sequential calls to Tailscale over a car SIM. */
    private const val PAIR_READ_TIMEOUT_MS = 45_000

    private const val DEFAULT_READ_TIMEOUT_MS = 10_000

    /**
     * A parsed daemon response.
     *
     * @param reason the daemon's machine-readable failure code (`not_configured`,
     *   `tag_not_owned`, `clock_skew`, …) — this is what the screen switches on to
     *   pick a message and a next action, never the human text.
     */
    data class Failure(val status: Int, val reason: String, val message: String)

    // ==================== SETUP ====================

    /** Owner-facing setup state, car identity, capabilities and the ACL grant. */
    fun status(): Result<JSONObject> = get("$BASE/status")

    /**
     * Save the OAuth client and pairing preferences.
     *
     * Pass a null [clientSecret] to leave the stored secret untouched — the
     * screen never reads it back, so re-saving a tag or a toggle must not
     * clear it.
     */
    fun saveConfig(
        clientId: String? = null,
        clientSecret: String? = null,
        phoneTag: String? = null,
        carTag: String? = null,
        shareDeviceToken: Boolean? = null,
        lanPairing: Boolean? = null,
        carName: String? = null,
        carModel: String? = null,
    ): Result<JSONObject> {
        val body = JSONObject()
        clientId?.let { body.put("oauth_client_id", it) }
        clientSecret?.let { body.put("oauth_client_secret", it) }
        phoneTag?.let { body.put("phone_tag", it) }
        carTag?.let { body.put("car_tag", it) }
        shareDeviceToken?.let { body.put("share_device_token", it) }
        lanPairing?.let { body.put("lan_pairing", it) }
        carName?.let { body.put("car_name", it) }
        carModel?.let { body.put("car_model", it) }
        return send("POST", "$BASE/config", body)
    }

    /**
     * Forget the OAuth client. Does **not** deauthorize already-paired phones —
     * it only stops new ones being paired. The screen must say so.
     */
    fun clearConfig(): Result<JSONObject> = send("DELETE", "$BASE/config", null)

    // ==================== PAIRING ====================

    /**
     * Mint a key and issue a pairing session. The response carries `uri` (the QR
     * payload) and `expires_at`; on failure, `reason` selects the screen's error
     * state.
     */
    fun startPairing(): Result<JSONObject> =
        send("POST", "$BASE/pair/start", null, readTimeoutMs = PAIR_READ_TIMEOUT_MS)

    /** Poll for the countdown and for the ISSUED → CONSUMED transition. */
    fun pairingSession(): Result<JSONObject> = get("$BASE/pair/session")

    /**
     * Clear the QR and delete the key. Called on expiry, on navigating away and
     * on screen sleep — both halves, every time.
     */
    fun cancelPairing(reason: String): Result<JSONObject> =
        send("POST", "$BASE/pair/cancel", JSONObject().put("reason", reason))

    // ==================== DEVICES ====================

    fun devices(): Result<JSONObject> = get("$BASE/devices")

    /**
     * Revoke a phone: registry row *and* tailnet node, in one action. Fails
     * without marking the row if the tailnet half fails, so the two halves can
     * never disagree.
     */
    fun revoke(deviceId: String): Result<JSONObject> =
        send("POST", "$BASE/devices/${enc(deviceId)}/revoke", null, readTimeoutMs = 20_000)

    /** Drop an already-revoked row. Refused by the daemon for a live device. */
    fun forget(deviceId: String): Result<JSONObject> =
        send("POST", "$BASE/devices/${enc(deviceId)}/forget", null)

    // ==================== PLUMBING ====================

    private fun get(path: String): Result<JSONObject> = send("GET", path, null)

    private fun send(
        method: String,
        path: String,
        body: JSONObject?,
        readTimeoutMs: Int = DEFAULT_READ_TIMEOUT_MS,
    ): Result<JSONObject> {
        var conn: java.net.HttpURLConnection? = null
        return try {
            conn = DaemonHttpClient.open(path, method, connectTimeoutMs = 3000, readTimeoutMs = readTimeoutMs)
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            // A 4xx/5xx puts the body on the error stream, and that body is where
            // the daemon's `reason` lives — so read whichever stream is populated.
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.let {
                BufferedReader(InputStreamReader(it, Charsets.UTF_8)).use(BufferedReader::readText)
            }.orEmpty()

            val json = if (text.isBlank()) JSONObject() else runCatching { JSONObject(text) }.getOrNull()
            if (status in 200..299) {
                Result.success(json ?: JSONObject())
            } else {
                Result.failure(
                    OverlinkException(
                        Failure(
                            status,
                            json?.optString("reason").orEmpty().ifEmpty { "http_$status" },
                            json?.optString("error").orEmpty().ifEmpty { "Request failed (HTTP $status)" },
                        )
                    )
                )
            }
        } catch (e: Exception) {
            // The daemon being down is the common case here, not a bug — the
            // pairing screen is reachable before it has booted.
            Result.failure(
                OverlinkException(
                    Failure(0, "daemon_unreachable",
                        "OverDrive's background service is not responding. Start the daemon and try again.")
                )
            )
        } finally {
            conn?.disconnect()
        }
    }

    private fun enc(s: String): String =
        java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    /** Carries [Failure] so callers can switch on `reason` rather than on text. */
    class OverlinkException(val failure: Failure) : Exception(failure.message)
}

/** Convenience for `Result.failure` payloads produced by [OverlinkClient]. */
val Throwable.overlinkFailure: OverlinkClient.Failure?
    get() = (this as? OverlinkClient.OverlinkException)?.failure
