package com.overdrive.app.ui.fragment.settings

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.overdrive.app.R
import com.overdrive.app.overlink.OverlinkClient
import com.overdrive.app.overlink.overlinkFailure
import com.overdrive.app.ui.util.QrCodeGenerator
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Settings → Tailscale → Phone pairing.
 *
 * Owns the *presentation* of pairing only. The nonce lifecycle, the Tailscale
 * API credentials and the device registry all live in the daemon (see
 * `OverlinkPairingManager`); this screen drives them through [OverlinkClient]
 * over authenticated loopback and polls for the countdown.
 *
 * Two behaviours here are load-bearing rather than cosmetic:
 *
 * * **Every exit path cancels the session.** Navigating away, the screen
 *   sleeping, or the countdown running out all clear the QR *and* delete the
 *   minted key. Clearing without deleting leaves a live credential; deleting
 *   without clearing leaves a dead QR that users keep scanning and reporting as
 *   broken.
 * * **Failures are distinct.** Each cause gets its own message and its own next
 *   action — the tag-not-in-tagOwners case in particular, which is the common
 *   first-run failure and close to undiagnosable behind a generic "mint failed".
 */
class PhonePairingFragment : Fragment() {

    /** Countdown tick. One second, because the countdown is displayed in seconds. */
    private val pollIntervalMs = 1_000L

    private val mainHandler = Handler(Looper.getMainLooper())
    private var io: ExecutorService? = null

    private lateinit var tvCarState: TextView
    private lateinit var tvCarIdentity: TextView
    private lateinit var warnUntagged: View
    private lateinit var btnPairPhone: MaterialButton
    private lateinit var pairProgress: View
    private lateinit var pairError: View
    private lateinit var tvPairError: TextView
    private lateinit var btnPairErrorAction: MaterialButton
    private lateinit var qrContainer: View
    private lateinit var ivPairQr: ImageView
    private lateinit var tvCountdown: TextView
    private lateinit var btnCancelPairing: MaterialButton
    private lateinit var pairSuccess: View
    private lateinit var tvPairSuccess: TextView
    private lateinit var rowShareToken: View
    private lateinit var swShareToken: MaterialSwitch
    private lateinit var rowLanPairing: View
    private lateinit var swLanPairing: MaterialSwitch
    private lateinit var etClientId: TextInputEditText
    private lateinit var etClientSecret: TextInputEditText
    private lateinit var etPhoneTag: TextInputEditText
    private lateinit var btnSaveSetup: MaterialButton
    private lateinit var btnForgetClient: MaterialButton
    private lateinit var tvAclGrant: TextView
    private lateinit var btnCopyGrant: MaterialButton
    private lateinit var tvNoDevices: TextView
    private lateinit var devicesContainer: LinearLayout

    /** True while a pairing session is on screen, so exit paths know to cancel. */
    private var sessionActive = false

    /** Guards the switch listeners while a failed write reverts the control. */
    private var applyingOptions = false

    private var aclGrant: String = ""

    private val poll = object : Runnable {
        override fun run() {
            refreshSession()
            if (sessionActive) mainHandler.postDelayed(this, pollIntervalMs)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_phone_pairing, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        io = Executors.newSingleThreadExecutor()
        bindViews(view)
        wireActions()
        loadStatus()
        loadDevices()
    }

    override fun onPause() {
        super.onPause()
        // Screen sleep and navigating away are the same thing from the key's
        // point of view: the QR is no longer in front of anyone, so it must not
        // stay live. onPause covers both, plus the app being backgrounded.
        if (sessionActive) cancelSession("screen left the pairing page")
    }

    override fun onDestroyView() {
        super.onDestroyView()
        mainHandler.removeCallbacksAndMessages(null)
        io?.shutdownNow()
        io = null
    }

    // ==================== BINDING ====================

    private fun bindViews(v: View) {
        tvCarState = v.findViewById(R.id.tvCarState)
        tvCarIdentity = v.findViewById(R.id.tvCarIdentity)
        warnUntagged = v.findViewById(R.id.warnUntagged)
        btnPairPhone = v.findViewById(R.id.btnPairPhone)
        pairProgress = v.findViewById(R.id.pairProgress)
        pairError = v.findViewById(R.id.pairError)
        tvPairError = v.findViewById(R.id.tvPairError)
        btnPairErrorAction = v.findViewById(R.id.btnPairErrorAction)
        qrContainer = v.findViewById(R.id.qrContainer)
        ivPairQr = v.findViewById(R.id.ivPairQr)
        tvCountdown = v.findViewById(R.id.tvCountdown)
        btnCancelPairing = v.findViewById(R.id.btnCancelPairing)
        pairSuccess = v.findViewById(R.id.pairSuccess)
        tvPairSuccess = v.findViewById(R.id.tvPairSuccess)
        rowShareToken = v.findViewById(R.id.rowShareToken)
        swShareToken = v.findViewById(R.id.swShareToken)
        rowLanPairing = v.findViewById(R.id.rowLanPairing)
        swLanPairing = v.findViewById(R.id.swLanPairing)
        etClientId = v.findViewById(R.id.etClientId)
        etClientSecret = v.findViewById(R.id.etClientSecret)
        etPhoneTag = v.findViewById(R.id.etPhoneTag)
        btnSaveSetup = v.findViewById(R.id.btnSaveSetup)
        btnForgetClient = v.findViewById(R.id.btnForgetClient)
        tvAclGrant = v.findViewById(R.id.tvAclGrant)
        btnCopyGrant = v.findViewById(R.id.btnCopyGrant)
        tvNoDevices = v.findViewById(R.id.tvNoDevices)
        devicesContainer = v.findViewById(R.id.devicesContainer)
    }

    private fun wireActions() {
        btnPairPhone.setOnClickListener { startPairing() }
        btnCancelPairing.setOnClickListener { cancelSession("owner cancelled") }
        btnSaveSetup.setOnClickListener { saveSetup() }
        btnForgetClient.setOnClickListener { confirmForgetClient() }
        btnCopyGrant.setOnClickListener { copyToClipboard("tailnet policy", aclGrant, R.string.pairing_grant_copied) }
        rowShareToken.setOnClickListener { if (!applyingOptions) toggleShareToken() }
        rowLanPairing.setOnClickListener { if (!applyingOptions) toggleLanPairing() }
    }

    // ==================== STATUS ====================

    private fun loadStatus() {
        runIo {
            val result = OverlinkClient.status()
            onMain {
                result.onSuccess { renderStatus(it) }
                    .onFailure { showError(it.overlinkFailure?.message ?: it.message.orEmpty(), null) }
            }
        }
    }

    private fun renderStatus(status: JSONObject) {
        val car = status.optJSONObject("car") ?: JSONObject()
        val running = car.optBoolean("running", false)

        tvCarState.text = when {
            !running && car.optString("backend_state") == "Unreachable" ->
                getString(R.string.pairing_car_unreachable)
            !running -> getString(R.string.pairing_car_not_joined)
            else -> getString(R.string.pairing_car_ready, car.optString("fqdn", "?"))
        }

        // Node ID and address stay visible whenever we know them: they are the
        // manual-pairing fallback, so the owner never has to leave this screen
        // to read them off another surface.
        val nodeId = car.optString("node_id", "")
        val tsIp = car.optString("ts_ip", "")
        if (nodeId.isNotEmpty() && tsIp.isNotEmpty()) {
            tvCarIdentity.text = getString(R.string.pairing_car_identity_fmt, nodeId, tsIp)
            tvCarIdentity.visibility = View.VISIBLE
        } else {
            tvCarIdentity.visibility = View.GONE
        }

        warnUntagged.visibility =
            if (running && !car.optBoolean("tagged", false)) View.VISIBLE else View.GONE

        // Pairing is only offered when the car can actually be reached.
        btnPairPhone.isEnabled = car.optBoolean("complete", false) && status.optBoolean("configured", false)

        applyingOptions = true
        swShareToken.isChecked = status.optBoolean("share_device_token", true)
        swLanPairing.isChecked = status.optBoolean("lan_pairing", false)
        applyingOptions = false

        // Never populate the secret field — the daemon does not return it, and a
        // blank field is what tells the save path to leave the stored one alone.
        etClientId.setText(status.optString("oauth_client_id", ""))
        etPhoneTag.setText(status.optString("phone_tag", ""))

        aclGrant = status.optString("acl_grant", "")
        tvAclGrant.text = aclGrant
    }

    private fun saveSetup() {
        val clientId = etClientId.text?.toString()?.trim().orEmpty()
        val secret = etClientSecret.text?.toString()?.trim().orEmpty()
        val tag = etPhoneTag.text?.toString()?.trim().orEmpty()

        btnSaveSetup.isEnabled = false
        runIo {
            val result = OverlinkClient.saveConfig(
                clientId = clientId,
                clientSecret = secret.ifEmpty { null },
                phoneTag = tag.ifEmpty { null },
            )
            onMain {
                btnSaveSetup.isEnabled = true
                result.onSuccess {
                    // Wipe the secret field once it is stored, so it is never
                    // sitting in a view for the next person at the head unit.
                    etClientSecret.setText("")
                    renderStatus(it)
                    toast(getString(R.string.pairing_saved))
                }.onFailure { e ->
                    val f = e.overlinkFailure
                    toast(
                        if (f?.reason == "bad_tag") getString(R.string.pairing_bad_tag)
                        else f?.message ?: e.message.orEmpty()
                    )
                }
            }
        }
    }

    private fun confirmForgetClient() {
        val ctx = context ?: return
        MaterialAlertDialogBuilder(ctx, R.style.Theme_Overdrive_M3_Dialog)
            .setIcon(R.drawable.ic_warning)
            .setTitle(R.string.pairing_forget_client_title)
            // Worth restating, because it genuinely surprises people: removing
            // the OAuth client does not deauthorize already-paired phones.
            .setMessage(R.string.pairing_forget_client_message)
            .setPositiveButton(R.string.pairing_action_forget_client) { _, _ ->
                runIo {
                    OverlinkClient.clearConfig()
                    onMain {
                        etClientId.setText("")
                        etClientSecret.setText("")
                        loadStatus()
                    }
                }
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun toggleShareToken() {
        val next = !swShareToken.isChecked
        applyingOptions = true
        swShareToken.isChecked = next
        runIo {
            val result = OverlinkClient.saveConfig(shareDeviceToken = next)
            onMain {
                applyingOptions = true
                result.onFailure { swShareToken.isChecked = !next }
                applyingOptions = false
            }
        }
        applyingOptions = false
    }

    private fun toggleLanPairing() {
        val next = !swLanPairing.isChecked
        applyingOptions = true
        swLanPairing.isChecked = next
        runIo {
            val result = OverlinkClient.saveConfig(lanPairing = next)
            onMain {
                applyingOptions = true
                result.onFailure { swLanPairing.isChecked = !next }
                applyingOptions = false
            }
        }
        applyingOptions = false
    }

    // ==================== PAIRING ====================

    private fun startPairing() {
        pairError.visibility = View.GONE
        pairSuccess.visibility = View.GONE
        qrContainer.visibility = View.GONE
        pairProgress.visibility = View.VISIBLE
        btnPairPhone.isEnabled = false

        runIo {
            val result = OverlinkClient.startPairing()
            onMain {
                pairProgress.visibility = View.GONE
                btnPairPhone.isEnabled = true
                result.onSuccess { showQr(it) }.onFailure { renderPairFailure(it) }
            }
        }
    }

    private fun showQr(session: JSONObject) {
        // Prefer the LAN form when the owner asked for it: the code then carries
        // an address and a single-use token instead of the key itself.
        val uri = session.optString("lan_uri", "").ifEmpty { session.optString("uri", "") }
        if (uri.isEmpty()) {
            showError(getString(R.string.pairing_expired), null)
            return
        }
        val px = resources.getDimensionPixelSize(R.dimen.pairing_qr_size)
        val bitmap = QrCodeGenerator.generateDarkTheme(uri, px)
        if (bitmap == null) {
            showError(getString(R.string.pairing_expired), null)
            return
        }

        ivPairQr.setImageBitmap(bitmap)
        qrContainer.visibility = View.VISIBLE
        btnPairPhone.setText(R.string.pairing_action_pair_again)
        renderCountdown(session.optInt("remaining_seconds", 0))

        sessionActive = true
        mainHandler.removeCallbacks(poll)
        mainHandler.postDelayed(poll, pollIntervalMs)
    }

    /** Poll the daemon for the countdown and the ISSUED → CONSUMED transition. */
    private fun refreshSession() {
        runIo {
            val result = OverlinkClient.pairingSession()
            onMain {
                result.onSuccess { s ->
                    when (s.optString("state", "idle")) {
                        "issued" -> renderCountdown(s.optInt("remaining_seconds", 0))
                        "consumed" -> onPaired(s)
                        else -> onSessionEnded()
                    }
                }.onFailure { onSessionEnded() }
            }
        }
    }

    private fun renderCountdown(remaining: Int) {
        tvCountdown.text = getString(R.string.pairing_countdown_fmt, remaining / 60, remaining % 60)
    }

    private fun onPaired(session: JSONObject) {
        sessionActive = false
        mainHandler.removeCallbacks(poll)
        clearQr()

        val label = session.optJSONObject("paired_device")?.optString("label").orEmpty()
        tvPairSuccess.text = getString(
            R.string.pairing_paired_fmt,
            label.ifEmpty { getString(R.string.pairing_overline_devices) },
        )
        pairSuccess.visibility = View.VISIBLE
        loadDevices()
    }

    /** The countdown ran out, or the daemon dropped the session. */
    private fun onSessionEnded() {
        if (!sessionActive) return
        sessionActive = false
        mainHandler.removeCallbacks(poll)
        clearQr()
        showError(getString(R.string.pairing_expired), null)
    }

    /**
     * Ask the daemon to end the session. It deletes the key; we clear the QR.
     * Both halves, every time.
     */
    private fun cancelSession(reason: String) {
        sessionActive = false
        mainHandler.removeCallbacks(poll)
        clearQr()
        // Fire-and-forget on the IO executor: this runs from onPause, where
        // blocking the main thread would stall the fragment transition. The
        // daemon expires the session on its own timer regardless, so a dropped
        // request costs at most the remainder of the 300 seconds.
        val executor = io ?: return
        if (executor.isShutdown) return
        executor.execute { runCatching { OverlinkClient.cancelPairing(reason) } }
    }

    private fun clearQr() {
        if (view == null) return
        qrContainer.visibility = View.GONE
        ivPairQr.setImageDrawable(null)
        btnPairPhone.setText(R.string.pairing_action_pair)
    }

    /**
     * Each failure gets its own message and its own next action. A generic
     * "pairing failed" here would make the common tag misconfiguration close to
     * undiagnosable.
     */
    private fun renderPairFailure(e: Throwable) {
        val failure = e.overlinkFailure
        val message = failure?.message ?: e.message.orEmpty()
        when (failure?.reason) {
            "not_configured" -> showError(message, R.string.pairing_error_action_setup) {
                etClientId.requestFocus()
            }
            "tag_not_owned" -> showError(message, R.string.pairing_error_action_grant) {
                tvAclGrant.requestFocus()
                copyToClipboard("tailnet policy", aclGrant, R.string.pairing_grant_copied)
            }
            "car_not_on_tailnet", "car_identity_incomplete" ->
                showError(message, R.string.pairing_error_action_tailscale) { loadStatus() }
            "bad_credentials" -> showError(message, R.string.pairing_error_action_setup) {
                etClientSecret.requestFocus()
            }
            else -> showError(message, R.string.pairing_error_action_retry) { startPairing() }
        }
    }

    private fun showError(message: String, actionLabel: Int?, action: (() -> Unit)? = null) {
        if (view == null) return
        tvPairError.text = message
        pairError.visibility = View.VISIBLE
        if (actionLabel != null && action != null) {
            btnPairErrorAction.setText(actionLabel)
            btnPairErrorAction.visibility = View.VISIBLE
            btnPairErrorAction.setOnClickListener { action() }
        } else {
            btnPairErrorAction.visibility = View.GONE
        }
    }

    // ==================== PAIRED DEVICES ====================

    private fun loadDevices() {
        runIo {
            val result = OverlinkClient.devices()
            onMain { result.onSuccess { renderDevices(it) } }
        }
    }

    private fun renderDevices(payload: JSONObject) {
        if (view == null) return
        val devices = payload.optJSONArray("devices")
        devicesContainer.removeAllViews()

        if (devices == null || devices.length() == 0) {
            tvNoDevices.visibility = View.VISIBLE
            return
        }
        tvNoDevices.visibility = View.GONE

        val inflater = LayoutInflater.from(requireContext())
        for (i in 0 until devices.length()) {
            val d = devices.optJSONObject(i) ?: continue
            val row = inflater.inflate(R.layout.item_paired_device, devicesContainer, false)
            val revoked = d.optBoolean("revoked", false)
            val deviceId = d.optString("device_id", "")
            val label = d.optString("label", "").ifEmpty { deviceId }

            row.findViewById<TextView>(R.id.tvDeviceLabel).text = label
            row.findViewById<TextView>(R.id.tvDeviceMeta).text = getString(
                R.string.pairing_device_meta_fmt,
                if (revoked) getString(R.string.pairing_device_revoked) else relativeLastSeen(d.optLong("last_seen", 0)),
                d.optString("app_version", "").ifEmpty { d.optString("platform", "") },
            )

            // A revoked row has nothing left to revoke; all it can do is go away.
            row.findViewById<MaterialButton>(R.id.btnRevokeDevice).apply {
                visibility = if (revoked) View.GONE else View.VISIBLE
                setOnClickListener { confirmRevoke(deviceId, label) }
            }
            row.findViewById<MaterialButton>(R.id.btnForgetDevice).apply {
                visibility = if (revoked) View.VISIBLE else View.GONE
                setOnClickListener { forgetDevice(deviceId) }
            }
            devicesContainer.addView(row)
        }
    }

    private fun confirmRevoke(deviceId: String, label: String) {
        val ctx = context ?: return
        MaterialAlertDialogBuilder(ctx, R.style.Theme_Overdrive_M3_Dialog)
            .setIcon(R.drawable.ic_warning)
            .setTitle(getString(R.string.pairing_revoke_title, label))
            .setMessage(R.string.pairing_revoke_message)
            .setPositiveButton(R.string.pairing_action_revoke) { _, _ -> revokeDevice(deviceId, label) }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun revokeDevice(deviceId: String, label: String) {
        runIo {
            val result = OverlinkClient.revoke(deviceId)
            onMain {
                result.onSuccess {
                    renderDevices(it)
                    toast(getString(R.string.pairing_revoked_fmt, label))
                }.onFailure { e ->
                    // The daemon leaves BOTH halves untouched when the tailnet
                    // delete fails, so this really is "nothing happened" rather
                    // than a partial state the user has to reason about.
                    toast(getString(
                        R.string.pairing_revoke_failed_fmt,
                        e.overlinkFailure?.message ?: e.message.orEmpty(),
                    ))
                }
            }
        }
    }

    private fun forgetDevice(deviceId: String) {
        runIo {
            val result = OverlinkClient.forget(deviceId)
            onMain { result.onSuccess { renderDevices(it) } }
        }
    }

    private fun relativeLastSeen(epochSeconds: Long): CharSequence {
        if (epochSeconds <= 0) return getString(R.string.pairing_device_never_seen)
        return android.text.format.DateUtils.getRelativeTimeSpanString(
            epochSeconds * 1000L,
            System.currentTimeMillis(),
            android.text.format.DateUtils.MINUTE_IN_MILLIS,
        )
    }

    // ==================== PLUMBING ====================

    private fun runIo(block: () -> Unit) {
        val executor = io ?: return
        if (executor.isShutdown) return
        executor.execute { runCatching(block) }
    }

    /** Hop to the main thread, dropping the work if the view is already gone. */
    private fun onMain(block: () -> Unit) {
        mainHandler.post { if (view != null && isAdded) block() }
    }

    private fun copyToClipboard(label: String, value: String, toastRes: Int) {
        if (value.isEmpty()) return
        val ctx = context ?: return
        val clip = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        clip.setPrimaryClip(ClipData.newPlainText(label, value))
        toast(getString(toastRes))
    }

    private fun toast(message: String) {
        val ctx = context?.applicationContext ?: return
        if (message.isNotEmpty()) Toast.makeText(ctx, message, Toast.LENGTH_SHORT).show()
    }
}
