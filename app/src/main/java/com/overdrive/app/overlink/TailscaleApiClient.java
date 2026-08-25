package com.overdrive.app.overlink;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * Minimal OkHttp client for {@code api.tailscale.com} (spec §4.2, §4.5, §5.3).
 *
 * <p>This is the one genuinely new piece of machinery Overlink needs. OverDrive
 * authenticates to Tailscale interactively today — {@code tailscale login
 * --hostname overdrive}, with {@link com.overdrive.app.launcher.TailscaleLauncher}
 * scraping {@code Log in at:} out of {@code tailscale status}. There is no OAuth
 * client, no API token and no key minting anywhere else in the tree.
 *
 * <p>Everything here is blocking. Callers must be off the UI thread; the
 * pairing flow can be three round trips over a car SIM (§11.3).
 *
 * <p>Errors are surfaced as {@link ApiException} carrying the HTTP status and,
 * where Tailscale supplied one, its message — {@link OverlinkPairingManager}
 * maps those to the distinct failure states in §11.6 (the "tag not in tagOwners"
 * case in particular, which is the common first-run failure and close to
 * undiagnosable behind a generic "mint failed").
 */
public final class TailscaleApiClient {

    private static final String BASE = "https://api.tailscale.com/api/v2";
    private static final String TOKEN_URL = BASE + "/oauth/token";

    /** {@code -} resolves to the tailnet the credential belongs to. */
    private static final String TAILNET = "-";

    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    /**
     * Refresh a little before the token actually dies so a mint that starts
     * just under the wire doesn't fail mid-flight.
     */
    private static final long TOKEN_SKEW_MS = 30_000L;

    private static final OkHttpClient HTTP = new OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build();

    /**
     * Tighter budget for the §4.5 device lookup, which runs <em>inside</em> a
     * phone's registration request rather than on a settings screen. The facts
     * it fetches are advisory — the phone treats them as "unknown" when absent —
     * so a slow control plane must cost the registration a few seconds at most,
     * never the whole HTTP response window. Shares {@link #HTTP}'s connection
     * pool and dispatcher via {@code newBuilder()}.
     */
    private static final OkHttpClient LOOKUP_HTTP = HTTP.newBuilder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .build();

    private final String clientId;
    private final String clientSecret;

    private String accessToken;
    private long accessTokenExpiresAt;

    /**
     * Signed difference between this head unit's clock and Tailscale's, measured
     * from the {@code Date} response header on the token exchange. Key expiry is
     * enforced against real time, so a badly wrong clock renders a QR that is
     * already dead — see {@link #clockSkewMs()}.
     */
    private volatile long clockSkewMs;
    private volatile boolean clockSkewKnown;

    public TailscaleApiClient(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /** Build a client from stored credentials, or null when pairing isn't set up. */
    public static TailscaleApiClient fromConfig() {
        if (!OverlinkConfig.isConfigured()) return null;
        return new TailscaleApiClient(OverlinkConfig.clientId(), OverlinkConfig.clientSecret());
    }

    // ==================== ERRORS ====================

    /** A failed Tailscale API call. {@link #status} is 0 for transport failures. */
    public static class ApiException extends Exception {
        public final int status;
        /** Tailscale's own error text when it supplied one, else null. */
        public final String apiMessage;

        ApiException(int status, String apiMessage, String message) {
            super(message);
            this.status = status;
            this.apiMessage = apiMessage;
        }

        /** True when the failure is the tag missing from {@code tagOwners} (§11.6). */
        public boolean isTagOwnershipError() {
            String m = apiMessage != null ? apiMessage.toLowerCase(java.util.Locale.US) : "";
            return m.contains("tagowner") || m.contains("tag owner")
                    || (m.contains("tag") && (m.contains("not permitted")
                        || m.contains("invalid") || m.contains("unauthorized")));
        }

        /** True when the OAuth credentials themselves were rejected. */
        public boolean isCredentialError() {
            return status == 401 || status == 403;
        }

        /** True when nothing reached Tailscale at all — the car has no internet. */
        public boolean isOffline() {
            return status == 0;
        }
    }

    // ==================== STEP 1 — ACCESS TOKEN ====================

    /**
     * Exchange the OAuth client credentials for a bearer token, reusing a
     * still-valid one. Tailscale tokens are short-lived (typically an hour), and
     * a pairing session can outlive one, so this refreshes on demand rather than
     * caching for the process lifetime.
     */
    public synchronized String accessToken() throws ApiException {
        long now = System.currentTimeMillis();
        if (accessToken != null && now < accessTokenExpiresAt - TOKEN_SKEW_MS) {
            return accessToken;
        }
        RequestBody form = new FormBody.Builder()
                .add("grant_type", "client_credentials")
                .add("client_id", clientId)
                .add("client_secret", clientSecret)
                .build();
        Request req = new Request.Builder()
                .url(TOKEN_URL)
                .post(form)
                .build();

        JSONObject json = execute(req, "oauth/token", this);
        String token = json.optString("access_token", "");
        if (token.isEmpty()) {
            throw new ApiException(200, null, "Tailscale returned no access_token");
        }
        // expires_in is seconds; default to 30 min if absent so we still refresh.
        long expiresIn = json.optLong("expires_in", 1800L);
        this.accessToken = token;
        this.accessTokenExpiresAt = now + (expiresIn * 1000L);
        return token;
    }

    /** Drop the cached token so the next call re-authenticates. */
    public synchronized void invalidateToken() {
        accessToken = null;
        accessTokenExpiresAt = 0;
    }

    /**
     * Local clock minus Tailscale's clock, in milliseconds, or 0 when unknown.
     * Positive means this head unit is running fast.
     */
    public long clockSkewMs() {
        return clockSkewKnown ? clockSkewMs : 0L;
    }

    public boolean isClockSkewKnown() {
        return clockSkewKnown;
    }

    private void recordClockSkew(Response resp) {
        try {
            java.util.Date serverDate = resp.headers().getDate("Date");
            if (serverDate == null) return;
            clockSkewMs = System.currentTimeMillis() - serverDate.getTime();
            clockSkewKnown = true;
        } catch (Exception ignored) {
            // A missing or unparseable Date header just leaves skew unknown.
        }
    }

    // ==================== STEP 2 — MINT A PAIRING KEY ====================

    /** A freshly minted auth key. {@link #secret} is shown exactly once. */
    public static final class MintedKey {
        /** Key ID, needed for the §4.2 step-5 delete. */
        public final String id;
        /** The {@code tskey-auth-…} secret that goes in the QR. */
        public final String secret;

        MintedKey(String id, String secret) {
            this.id = id;
            this.secret = secret;
        }
    }

    /**
     * Mint a one-off, pre-authorized, tagged auth key.
     *
     * <p><strong>{@code ephemeral} is hard-coded false, and this is settled, not
     * a preference.</strong> Tailscale marks nodes ephemeral based on their
     * registration method, not on client choice — there is no way for the phone
     * to register non-ephemeral using an ephemeral key. Ephemeral devices are
     * auto-removed 30–60 minutes after their last activity and get a new IP when
     * recreated. A phone is offline constantly, so an ephemeral phone node works
     * for a week and then silently stops: the worst failure shape there is,
     * because it looks like the app broke rather than like a misconfiguration.
     *
     * <p>Containment does not need ephemerality. {@code reusable: false} bounds
     * the key to one device, {@code expirySeconds} bounds it to five minutes, and
     * {@link #deleteKey} removes it on use.
     */
    public MintedKey mintPairingKey(String tag, int expirySeconds, String description)
            throws ApiException {
        JSONObject create = new JSONObject();
        JSONObject devices = new JSONObject();
        JSONObject caps = new JSONObject();
        JSONObject body = new JSONObject();
        try {
            create.put("reusable", false);
            create.put("ephemeral", false);
            create.put("preauthorized", true);
            create.put("tags", new JSONArray().put(tag));
            devices.put("create", create);
            caps.put("devices", devices);
            body.put("capabilities", caps);
            body.put("expirySeconds", expirySeconds);
            body.put("description", description);
        } catch (Exception e) {
            throw new ApiException(0, null, "Failed to build key request: " + e.getMessage());
        }

        Request req = new Request.Builder()
                .url(BASE + "/tailnet/" + TAILNET + "/keys")
                .addHeader("Authorization", "Bearer " + accessToken())
                .post(RequestBody.create(body.toString(), JSON))
                .build();

        JSONObject json = execute(req, "mint key");
        String id = json.optString("id", "");
        String secret = json.optString("key", "");
        if (secret.isEmpty()) {
            throw new ApiException(200, null, "Tailscale returned no key material");
        }
        return new MintedKey(id, secret);
    }

    /**
     * Delete a minted key (§4.2 step 5). Best-effort by design: called from the
     * nonce-lifecycle cleanup path, where failing loudly would strand the UI.
     * Returns true when Tailscale confirmed the delete.
     */
    public boolean deleteKey(String keyId) {
        if (keyId == null || keyId.isEmpty()) return false;
        try {
            Request req = new Request.Builder()
                    .url(BASE + "/tailnet/" + TAILNET + "/keys/" + urlSegment(keyId))
                    .addHeader("Authorization", "Bearer " + accessToken())
                    .delete()
                    .build();
            try (Response resp = HTTP.newCall(req).execute()) {
                // 404 means it is already gone, which satisfies the intent.
                return resp.isSuccessful() || resp.code() == 404;
            }
        } catch (Exception e) {
            OverlinkConfig.log("key delete failed for " + keyId + ": " + e.getMessage());
            return false;
        }
    }

    // ==================== §4.5 — VERIFYING WHAT REGISTERED ====================

    /**
     * What control actually applied to a node — which is not necessarily what
     * was asked for. All three fields feed the phone's user-visible warnings,
     * which name the <em>car</em> as the place to fix it so the user is not sent
     * round a re-pair loop for something they cannot fix on the phone.
     */
    public static final class DeviceFacts {
        public final String nodeId;
        public final boolean ephemeral;
        /** ISO-8601 key expiry, or null when expiry is disabled (the tagged case). */
        public final String keyExpiry;
        public final List<String> tags;

        DeviceFacts(String nodeId, boolean ephemeral, String keyExpiry, List<String> tags) {
            this.nodeId = nodeId;
            this.ephemeral = ephemeral;
            this.keyExpiry = keyExpiry;
            this.tags = tags;
        }
    }

    /**
     * Look a device up by StableNodeID, falling back to a tailnet-IP match.
     *
     * <p>The phone cannot see its own ephemerality — {@code tsnet} does not
     * expose it. The car can, because it holds the API credentials. Matching on
     * the {@code node_id} the phone supplied at registration is a direct lookup;
     * {@code nodeIp} is carried as a fallback for a control plane that indexes
     * differently, and as a sanity check that the registering phone is the node
     * it claims to be.
     *
     * @return the facts, or null when no device matched.
     */
    public DeviceFacts findDevice(String nodeId, String nodeIp) throws ApiException {
        Request req = new Request.Builder()
                .url(BASE + "/tailnet/" + TAILNET + "/devices")
                .addHeader("Authorization", "Bearer " + accessToken())
                .get()
                .build();

        JSONObject json = execute(LOOKUP_HTTP, req, "list devices", null);
        JSONArray devices = json.optJSONArray("devices");
        if (devices == null) return null;

        DeviceFacts ipMatch = null;
        for (int i = 0; i < devices.length(); i++) {
            JSONObject d = devices.optJSONObject(i);
            if (d == null) continue;

            String id = d.optString("nodeId", "");
            if (nodeId != null && !nodeId.isEmpty() && nodeId.equals(id)) {
                return toFacts(d, id);
            }
            if (ipMatch == null && nodeIp != null && !nodeIp.isEmpty()) {
                JSONArray addrs = d.optJSONArray("addresses");
                if (addrs != null) {
                    for (int j = 0; j < addrs.length(); j++) {
                        if (nodeIp.equals(addrs.optString(j, null))) {
                            ipMatch = toFacts(d, id);
                            break;
                        }
                    }
                }
            }
        }
        return ipMatch;
    }

    private static DeviceFacts toFacts(JSONObject d, String id) {
        // Tailscale omits `expires` or sends the zero time when key expiry is
        // disabled, which is what a correctly tagged device looks like.
        String expires = d.optString("expires", "");
        if (expires.isEmpty() || expires.startsWith("0001-01-01")) expires = null;

        List<String> tags = new ArrayList<>();
        JSONArray t = d.optJSONArray("tags");
        if (t != null) {
            for (int i = 0; i < t.length(); i++) {
                String v = t.optString(i, null);
                if (v != null && !v.isEmpty()) tags.add(v);
            }
        }
        return new DeviceFacts(id, d.optBoolean("isEphemeral", false), expires, tags);
    }

    // ==================== §5.3 — REVOCATION ====================

    /**
     * Remove a node from the tailnet. This is the half of revocation that
     * actually cuts access; {@link DeviceRegistry} owns the other half and the
     * two are only ever surfaced as one action.
     *
     * @return true when the node is gone (including "was already gone")
     */
    public boolean deleteDevice(String nodeId) throws ApiException {
        if (nodeId == null || nodeId.isEmpty()) {
            throw new ApiException(0, null, "No node ID recorded for this device");
        }
        Request req = new Request.Builder()
                .url(BASE + "/device/" + urlSegment(nodeId))
                .addHeader("Authorization", "Bearer " + accessToken())
                .delete()
                .build();
        try (Response resp = HTTP.newCall(req).execute()) {
            if (resp.isSuccessful() || resp.code() == 404) return true;
            throw new ApiException(resp.code(), readError(resp),
                    "Tailscale refused to delete the device (HTTP " + resp.code() + ")");
        } catch (IOException e) {
            throw new ApiException(0, null, "Could not reach Tailscale: " + e.getMessage());
        }
    }

    // ==================== PLUMBING ====================

    private static JSONObject execute(Request req, String what) throws ApiException {
        return execute(HTTP, req, what, null);
    }

    private static JSONObject execute(Request req, String what, TailscaleApiClient skewSink)
            throws ApiException {
        return execute(HTTP, req, what, skewSink);
    }

    private static JSONObject execute(OkHttpClient http, Request req, String what,
                                      TailscaleApiClient skewSink) throws ApiException {
        try (Response resp = http.newCall(req).execute()) {
            if (skewSink != null) skewSink.recordClockSkew(resp);
            ResponseBody rb = resp.body();
            String text = rb != null ? rb.string() : "";
            if (!resp.isSuccessful()) {
                throw new ApiException(resp.code(), extractError(text),
                        "Tailscale " + what + " failed (HTTP " + resp.code() + ")");
            }
            if (text.isEmpty()) return new JSONObject();
            return new JSONObject(text);
        } catch (ApiException e) {
            throw e;
        } catch (IOException e) {
            throw new ApiException(0, null, "Could not reach Tailscale: " + e.getMessage());
        } catch (Exception e) {
            throw new ApiException(0, null, "Unreadable Tailscale response: " + e.getMessage());
        }
    }

    private static String readError(Response resp) {
        try {
            ResponseBody rb = resp.body();
            return rb != null ? extractError(rb.string()) : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Tailscale errors arrive as {@code {"message": "..."}}, occasionally as plain text. */
    private static String extractError(String text) {
        if (text == null || text.isEmpty()) return null;
        try {
            JSONObject j = new JSONObject(text);
            String m = j.optString("message", "");
            if (!m.isEmpty()) return m;
        } catch (Exception ignored) {
            // Not JSON — fall through and use the raw text.
        }
        return text.length() > 400 ? text.substring(0, 400) : text;
    }

    private static String urlSegment(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return s;
        }
    }
}
