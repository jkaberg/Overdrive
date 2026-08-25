package com.overdrive.app.overlink;

import android.util.Base64;

import com.overdrive.app.auth.AuthManager;
import com.overdrive.app.daemon.CameraDaemon;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.Locale;

/**
 * The pairing nonce lifecycle and QR payload builder (spec §4.2–§4.4, §11.4).
 *
 * <h3>Why this lives in the daemon</h3>
 * §11.1 sketches this as a Kotlin class in the settings UI. It is Java here, and
 * runs inside {@link CameraDaemon}, because the app and the daemon are separate
 * JVMs: the settings screen runs as the app UID, while the registration endpoint
 * that consumes the nonce is served by the daemon. Splitting the state machine
 * across two processes would mean persisting the nonce — and the minted auth key
 * — through the world-readable config file and inventing a cross-process
 * compare-and-set for §11.4's atomic consumption. Keeping the whole machine in
 * the daemon makes consumption a plain {@code synchronized} block, and means the
 * auth key never touches disk. The UI drives it over authenticated loopback via
 * {@link com.overdrive.app.util.DaemonHttpClient}.
 *
 * <h3>State machine (§11.4)</h3>
 * <pre>
 * ISSUED ──(register with matching nonce)──▶ CONSUMED ──▶ clear QR, delete key
 *    │
 *    ├──(300s elapsed)──────────▶ EXPIRED ──▶ clear QR, delete key
 *    ├──(screen sleep)──────────▶ EXPIRED ──▶ clear QR, delete key
 *    └──(owner navigates away)──▶ EXPIRED ──▶ clear QR, delete key
 * </pre>
 * At most one ISSUED session exists at a time — starting a new pairing expires
 * the previous one. A second registration carrying an already-consumed nonce is
 * rejected, which is what makes the replay test meaningful.
 */
public final class OverlinkPairingManager {

    /** Payload version the phone's parser expects. */
    public static final int PAYLOAD_VERSION = 1;

    /** Key lifetime and nonce lifetime, in seconds (§4.2). */
    public static final int PAIRING_TTL_SECONDS = 300;

    /**
     * Soft ceiling on the plain URI form. The phone accepts up to 2048 bytes, but
     * QR legibility collapses long before that and pairing has to work on a real
     * head unit, in sunlight, at arm's length. Past this we switch to the compact
     * base64 form, which {@code core/pairing.go} also decodes.
     */
    private static final int URI_SIZE_BUDGET = 800;

    /**
     * Reject a clock this far off Tailscale's before minting (§11.5). Key expiry
     * is enforced against real time, so past roughly a minute of skew the QR is
     * born dead and the user gets a mysterious rejection instead of an answer.
     */
    private static final long MAX_CLOCK_SKEW_MS = 60_000L;

    private static final SecureRandom RANDOM = new SecureRandom();

    public enum State { IDLE, ISSUED, CONSUMED, EXPIRED }

    // ==================== SESSION ====================

    /** One pairing attempt. Immutable except for {@link #state} and consumption. */
    public static final class Session {
        public final String nonce;
        /** Single-use token for the §4.6 LAN claim; null when LAN pairing is off. */
        public final String claimToken;
        public final String keyId;
        public final String authKey;
        public final String tag;
        public final CarIdentity car;
        public final long issuedAt;
        public final long expiresAt;
        /** The full §4.4 payload as JSON — also what the LAN claim endpoint serves. */
        public final JSONObject payload;
        public final String uri;

        State state = State.ISSUED;
        String consumedBy;
        boolean claimTokenUsed;

        Session(String nonce, String claimToken, String keyId, String authKey, String tag,
                CarIdentity car, long issuedAt, long expiresAt, JSONObject payload, String uri) {
            this.nonce = nonce;
            this.claimToken = claimToken;
            this.keyId = keyId;
            this.authKey = authKey;
            this.tag = tag;
            this.car = car;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.payload = payload;
            this.uri = uri;
        }

        public boolean isExpired(long now) {
            return now >= expiresAt;
        }

        public State state() {
            return state;
        }

        public String consumedBy() {
            return consumedBy;
        }
    }

    /** A pairing attempt that could not start, mapped to §11.6's failure states. */
    public static final class PairingException extends Exception {
        /** Stable machine-readable reason, e.g. {@code not_configured}, {@code tag_not_owned}. */
        public final String reason;

        PairingException(String reason, String message) {
            super(message);
            this.reason = reason;
        }
    }

    private static final Object LOCK = new Object();
    private static Session current;

    private OverlinkPairingManager() {}

    // ==================== START ====================

    /**
     * Mint a key and issue a fresh pairing session. Blocking — up to three round
     * trips to {@code api.tailscale.com} over what may be a car SIM, so callers
     * must be off the UI thread and show visible progress (§11.3).
     *
     * <p>Starting a new session expires any previous one, key deletion included.
     */
    public static Session start() throws PairingException {
        if (!OverlinkConfig.isConfigured()) {
            throw new PairingException("not_configured",
                    "Set up phone pairing first — OverDrive needs a Tailscale OAuth client "
                    + "to mint pairing keys.");
        }

        CarIdentity car = CarIdentity.read();
        if (!car.isRunning()) {
            throw new PairingException("car_not_on_tailnet",
                    "This car has not joined a tailnet yet.");
        }
        if (!car.isComplete()) {
            throw new PairingException("car_identity_incomplete",
                    "Tailscale is running but has not reported this car's address yet. "
                    + "Try again in a moment.");
        }

        TailscaleApiClient api = TailscaleApiClient.fromConfig();
        String tag = OverlinkConfig.phoneTag();
        String carName = displayName(car);

        TailscaleApiClient.MintedKey key;
        try {
            // The token exchange also gives us Tailscale's clock, so the skew
            // check below costs nothing extra.
            api.accessToken();
            if (api.isClockSkewKnown() && Math.abs(api.clockSkewMs()) > MAX_CLOCK_SKEW_MS) {
                long offBy = Math.abs(api.clockSkewMs()) / 1000L;
                throw new PairingException("clock_skew",
                        "The car's clock is off by about " + offBy + " seconds, so pairing codes "
                        + "will not work. Fix the time first.");
            }
            key = api.mintPairingKey(tag, PAIRING_TTL_SECONDS, describe(carName));
        } catch (TailscaleApiClient.ApiException e) {
            throw toPairingException(e, tag);
        }

        long now = System.currentTimeMillis();
        String nonce = randomToken();
        boolean lan = OverlinkConfig.lanPairingEnabled();
        String claimToken = lan ? randomToken() : null;

        JSONObject payload = buildPayload(nonce, key.secret, tag, car, carName);
        String uri = buildUri(payload);

        Session session = new Session(nonce, claimToken, key.id, key.secret, tag, car,
                now, now + (PAIRING_TTL_SECONDS * 1000L), payload, uri);

        Session previous;
        synchronized (LOCK) {
            previous = current;
            current = session;
        }
        // Expire the displaced session outside the lock — deleting its key is a
        // network call and must not block a concurrent registration.
        if (previous != null && previous.state == State.ISSUED) {
            retire(previous, State.EXPIRED, "superseded by a new pairing");
        }

        log("pairing issued, nonce=" + shortId(nonce) + " key=" + key.id
                + " tag=" + tag + " ttl=" + PAIRING_TTL_SECONDS + "s");
        return session;
    }

    // ==================== INSPECT ====================

    /**
     * The most recent session, or null. A session whose timer ran out while
     * nobody was looking is expired and its key deleted on the way past, so the
     * countdown reaching zero is enough to guarantee cleanup even if the UI
     * never comes back to cancel it.
     */
    public static Session active() {
        Session expiring = null;
        Session s;
        synchronized (LOCK) {
            s = current;
            if (s == null) return null;
            if (s.state == State.ISSUED && s.isExpired(System.currentTimeMillis())) {
                s.state = State.EXPIRED;
                expiring = s;
            }
        }
        if (expiring != null) retire(expiring, State.EXPIRED, "expired");
        return s;
    }

    /** Seconds left on the visible countdown, floored at 0. */
    public static int remainingSeconds(Session s) {
        if (s == null || s.state != State.ISSUED) return 0;
        long ms = s.expiresAt - System.currentTimeMillis();
        return ms <= 0 ? 0 : (int) Math.ceil(ms / 1000.0);
    }

    // ==================== CONSUME (§11.4) ====================

    /**
     * Atomically consume a nonce presented at registration.
     *
     * <p>Rejects a nonce that was never issued, has expired, or was already
     * consumed by a different device. A repeat from the <em>same</em> device is
     * accepted so a retried registration (dropped response, app restart during
     * the handshake) is not treated as an attack.
     *
     * @return true when the nonce was accepted.
     */
    public static boolean consumeNonce(String nonce, String deviceId) {
        if (nonce == null || nonce.isEmpty()) return false;
        Session toRetire = null;
        boolean accepted = false;

        synchronized (LOCK) {
            Session s = current;
            if (s == null || !constantTimeEquals(s.nonce, nonce)) return false;

            if (s.state == State.CONSUMED) {
                // Idempotent retry from the same install only.
                return deviceId != null && deviceId.equals(s.consumedBy);
            }
            if (s.state != State.ISSUED) return false;
            if (s.isExpired(System.currentTimeMillis())) {
                s.state = State.EXPIRED;
                toRetire = s;
            } else {
                s.state = State.CONSUMED;
                s.consumedBy = deviceId;
                toRetire = s;
                accepted = true;
            }
        }

        // §4.2 step 5 / §6.3: on consumption do not wait for the timer — clear
        // the QR and delete the key immediately. Off the lock; it is a network call.
        if (toRetire != null) {
            final Session s = toRetire;
            final boolean ok = accepted;
            new Thread(() -> retire(s, s.state, ok ? "consumed" : "expired"),
                    "OverlinkKeyCleanup").start();
        }
        return accepted;
    }

    /**
     * Consume the §4.6 LAN claim token. Single-use, atomic, and the nonce must
     * match the one in the same request — a mismatch is a crossed pairing attempt.
     *
     * @return the payload to serve, or null when the token is wrong, used or expired.
     */
    public static JSONObject claim(String token, String nonce) {
        synchronized (LOCK) {
            Session s = current;
            if (s == null || s.state != State.ISSUED) return null;
            if (s.claimToken == null || s.claimTokenUsed) return null;
            if (s.isExpired(System.currentTimeMillis())) return null;
            if (!constantTimeEquals(s.claimToken, token)) return null;
            if (!constantTimeEquals(s.nonce, nonce)) return null;
            s.claimTokenUsed = true;
            return s.payload;
        }
    }

    // ==================== CANCEL / EXPIRE ====================

    /**
     * End the active session — the owner navigated away, the screen slept, or the
     * countdown ran out. Clears the QR and deletes the key: both halves, every
     * time. Clearing without deleting leaves a live credential; deleting without
     * clearing leaves a dead QR that users keep scanning and reporting as broken.
     */
    public static void cancel(String why) {
        Session s;
        synchronized (LOCK) {
            s = current;
            if (s == null) return;
            if (s.state == State.ISSUED) s.state = State.EXPIRED;
            current = null;
        }
        retire(s, s.state, why != null ? why : "cancelled");
    }

    /**
     * Delete the minted key and drop the session from view. Idempotent and
     * best-effort: this runs from cleanup paths where failing loudly would
     * strand the UI, so a failed delete is logged and the key is left to its own
     * 300-second expiry.
     *
     * <p>A CONSUMED session stays addressable so the pairing screen can show
     * "Paired: Pixel 8" — its key is deleted either way.
     */
    private static void retire(Session s, State finalState, String why) {
        if (s == null) return;
        synchronized (LOCK) {
            if (current == s && finalState == State.EXPIRED) current = null;
        }
        TailscaleApiClient api = TailscaleApiClient.fromConfig();
        boolean deleted = api != null && api.deleteKey(s.keyId);
        log("pairing " + why + ", nonce=" + shortId(s.nonce)
                + " key=" + s.keyId + " deleted=" + deleted);
    }

    // ==================== PAYLOAD (§4.4) ====================

    /**
     * Build the pairing payload. Field names match the QR query parameters
     * exactly, because the §4.6 claim endpoint serves this same object as JSON.
     */
    private static JSONObject buildPayload(String nonce, String authKey, String tag,
                                           CarIdentity car, String carName) {
        JSONObject p = new JSONObject();
        try {
            p.put("v", PAYLOAD_VERSION);
            p.put("nonce", nonce);
            p.put("ak", authKey);
            p.put("tag", tag);
            p.put("node_id", car.nodeId);
            p.put("ts_ip", car.tailscaleIp);
            p.put("fqdn", car.fqdn);
            // Read from the running server — never hardcode 8080.
            p.put("port", CameraDaemon.HTTP_PORT);
            p.put("caps", new JSONArray(capabilities()));

            if (!carName.isEmpty()) p.put("car_name", carName);
            String model = OverlinkConfig.carModel();
            if (!model.isEmpty()) p.put("car_model", model);

            String lanIp = LanAddress.privateAddress();
            if (lanIp != null) p.put("lan_ip", lanIp);

            // §6: the device token, so the phone can log itself in and the user
            // never meets OverDrive's PIN prompt. Optional, defaulted on.
            if (OverlinkConfig.shareDeviceToken()) {
                String dt = deviceToken();
                if (dt != null && !dt.isEmpty()) p.put("dt", dt);
            }
            // `notify` is reserved and stays empty in v1.
        } catch (Exception e) {
            log("payload build failed: " + e.getMessage());
        }
        return p;
    }

    /**
     * Render the payload as the {@code overdrive://pair?…} URI, falling back to
     * the compact {@code ?b=<base64url(json)>} form when the query-string version
     * would push the QR past what a head-unit screen renders legibly.
     */
    static String buildUri(JSONObject payload) {
        StringBuilder sb = new StringBuilder("overdrive://pair?");
        // Deterministic order so the QR is stable for a given payload; `v` first
        // so a version mismatch is the first thing a parser sees.
        String[] order = {"v", "nonce", "ak", "tag", "node_id", "ts_ip", "fqdn", "port",
                          "lan_ip", "lan_hint", "car_name", "car_model", "caps", "dt"};
        boolean first = true;
        for (String key : order) {
            if (!payload.has(key)) continue;
            Object v = payload.opt(key);
            if (v == null || v == JSONObject.NULL) continue;
            String value;
            if (v instanceof JSONArray) {
                JSONArray a = (JSONArray) v;
                if (a.length() == 0) continue;
                StringBuilder joined = new StringBuilder();
                for (int i = 0; i < a.length(); i++) {
                    if (i > 0) joined.append(',');
                    joined.append(a.optString(i, ""));
                }
                value = joined.toString();
            } else {
                value = String.valueOf(v);
            }
            if (!first) sb.append('&');
            first = false;
            sb.append(key).append('=').append(urlEncode(value));
        }

        String uri = sb.toString();
        if (uri.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= URI_SIZE_BUDGET) {
            return uri;
        }
        return "overdrive://pair?b=" + base64Url(payload.toString());
    }

    /** The §4.6 LAN-pairing QR: an address and a single-use token, no key. */
    public static String buildLanUri(Session s) {
        String lan = LanAddress.privateAddress();
        if (lan == null || s.claimToken == null) return null;
        return "overdrive://pair?v=" + PAYLOAD_VERSION
                + "&src=lan"
                + "&addr=" + urlEncode(lan + ":" + CameraDaemon.HTTP_PORT)
                + "&t=" + urlEncode(s.claimToken)
                + "&nonce=" + urlEncode(s.nonce);
    }

    // ==================== CAPABILITIES (§7) ====================

    /**
     * What this build supports. The registration response is authoritative — the
     * QR is a snapshot from pairing time and the car may have been updated since,
     * so the phone overwrites its stored copy from the response.
     *
     * <p>Flags are additive and must never be removed once shipped: the phone
     * treats an absent flag as "not supported" and degrades, so removing one
     * silently disables a working feature.
     */
    public static java.util.List<String> capabilities() {
        java.util.List<String> caps = new java.util.ArrayList<>();
        caps.add("registry");
        caps.add("events");
        if (OverlinkConfig.shareDeviceToken() && deviceToken() != null) caps.add("auth_token");
        if (OverlinkConfig.lanPairingEnabled()) caps.add("lan_pairing");
        // `cloud` is v2 — not advertised until the car can proxy BYD Cloud calls.
        return caps;
    }

    // ==================== HELPERS ====================

    /**
     * OverDrive's stable device token (§6). A real credential: it grants full
     * dashboard access, and belongs in the QR only because the QR is a
     * five-minute one-off displayed on a screen the owner physically controls.
     * Never log it.
     */
    static String deviceToken() {
        try {
            AuthManager.AuthState state = AuthManager.getState();
            if (state == null) return null;
            String t = state.getDeviceToken();
            return (t == null || t.isEmpty()) ? null : t;
        } catch (Exception e) {
            return null;
        }
    }

    private static String displayName(CarIdentity car) {
        String configured = OverlinkConfig.carName();
        return !configured.isEmpty() ? configured : car.shortName();
    }

    private static String describe(String carName) {
        return "Overlink pairing — " + carName + " — " + iso8601Now();
    }

    private static String iso8601Now() {
        java.text.SimpleDateFormat f =
                new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        f.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return f.format(new java.util.Date());
    }

    /** 128 bits, URL-safe, matching the phone's {@code ^[A-Za-z0-9._~-]{8,128}$}. */
    static String randomToken() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.encodeToString(bytes, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static String base64Url(String json) {
        return Base64.encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /** Length-independent comparison so a token cannot be recovered by timing. */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] y = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int diff = x.length ^ y.length;
        for (int i = 0; i < x.length && i < y.length; i++) diff |= x[i] ^ y[i];
        return diff == 0;
    }

    private static PairingException toPairingException(TailscaleApiClient.ApiException e, String tag) {
        if (e.isOffline()) {
            return new PairingException("offline", "The car is offline — Tailscale could not be reached.");
        }
        if (e.isTagOwnershipError()) {
            // The common first-run failure. A generic "mint failed" here is close
            // to undiagnosable, so name the tag and point at the ACL grant.
            return new PairingException("tag_not_owned",
                    tag + " is not listed in tagOwners. Add the grant block from this screen "
                    + "to your tailnet policy, then try again.");
        }
        if (e.isCredentialError()) {
            return new PairingException("bad_credentials",
                    "Tailscale rejected these credentials. Check the OAuth client ID and secret.");
        }
        return new PairingException("mint_failed", e.getMessage());
    }

    /** Nonces are secrets; log a prefix so sessions stay traceable without leaking. */
    private static String shortId(String s) {
        if (s == null) return "?";
        return s.length() <= 6 ? "…" : s.substring(0, 6) + "…";
    }

    private static void log(String message) {
        OverlinkConfig.log(message);
    }
}
