package com.overdrive.app.server;

import com.overdrive.app.auth.AuthManager;
import com.overdrive.app.daemon.CameraDaemon;
import com.overdrive.app.notifications.NotificationStore;
import com.overdrive.app.overlink.CarIdentity;
import com.overdrive.app.overlink.DeviceRegistry;
import com.overdrive.app.overlink.LanAddress;
import com.overdrive.app.overlink.OverlinkConfig;
import com.overdrive.app.overlink.OverlinkPairingManager;
import com.overdrive.app.overlink.TailscaleApiClient;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.net.SocketAddress;
import java.util.Map;

/**
 * The Overlink companion-app API — everything under {@code /api/overlink/v1/*}.
 *
 * <h3>Endpoints</h3>
 * <table>
 *   <tr><td>{@code GET  /status}</td><td>owner-facing setup state, car identity, ACL grant</td></tr>
 *   <tr><td>{@code POST /config}</td><td>store OAuth client + pairing preferences</td></tr>
 *   <tr><td>{@code DELETE /config}</td><td>forget the OAuth client</td></tr>
 *   <tr><td>{@code POST /pair/start}</td><td>mint a key, issue a nonce, return the QR payload</td></tr>
 *   <tr><td>{@code GET  /pair/session}</td><td>countdown + state, for the pairing screen</td></tr>
 *   <tr><td>{@code POST /pair/cancel}</td><td>clear the QR and delete the key</td></tr>
 *   <tr><td>{@code GET  /pair/claim}</td><td><b>public</b> — §4.6 local-network pairing</td></tr>
 *   <tr><td>{@code POST /devices/register}</td><td><b>public path</b> — §5.1, guarded by JWT or nonce</td></tr>
 *   <tr><td>{@code GET  /devices}</td><td>paired-device list</td></tr>
 *   <tr><td>{@code POST /devices/{id}/revoke}</td><td>§5.3 — registry and tailnet, one action</td></tr>
 *   <tr><td>{@code POST /devices/{id}/forget}</td><td>drop a revoked row</td></tr>
 *   <tr><td>{@code GET  /events}</td><td>§8 — canonical event schema over the notification log</td></tr>
 * </table>
 *
 * <h3>Which channel each endpoint trusts</h3>
 * Two endpoints are listed in {@link AuthMiddleware}'s {@code PUBLIC_PATHS}
 * because neither can rely on a JWT: {@code /pair/claim} runs before the tunnel
 * exists, and {@code /devices/register} runs before the phone has a session
 * whenever the car omits {@code dt}. Each carries its own credential instead —
 * a single-use claim token and a single-use nonce respectively — and each is
 * additionally restricted by source address here. Everything else under
 * {@code /api/overlink/} stays behind normal auth.
 *
 * <p><b>Source-address note.</b> §11.2 asks for registration to be tailnet-only.
 * OverDrive runs {@code tailscaled --tun userspace-networking} (no root, so no
 * TUN device), which means inbound tailnet connections are terminated by
 * tailscaled's netstack and re-originated into loopback rather than arriving
 * from the peer's 100.64/10 address. So {@link #isTrustedTunnelSource} accepts
 * either a Tailscale peer address or loopback, and refuses a routable or
 * ordinary-LAN source. The nonce and the JWT remain the real guards; this is
 * defence in depth, not the primary check.
 */
public final class OverlinkApiHandler {

    private static final String PREFIX = "/api/overlink/v1";

    /** §4.6: the phone reads at most 64 KB, so keep the claim response small. */
    private static final int MAX_CLAIM_BYTES = 8 * 1024;

    /** §8: page size for the event feed. */
    private static final int DEFAULT_EVENT_LIMIT = 50;
    private static final int MAX_EVENT_LIMIT = 200;

    /** Signed-thumbnail TTL, matching the surveillance and proximity call sites. */
    private static final long THUMB_TOKEN_TTL_SEC = 600L;

    private OverlinkApiHandler() {}

    // ==================== DISPATCH ====================

    /**
     * @param clientAddress the peer socket address — load-bearing: the claim
     *                      endpoint must be served on the LAN while registration
     *                      and events must not be.
     * @return true when this handler produced a response.
     */
    public static boolean handle(String method, String path, String body, OutputStream out,
                                 SocketAddress clientAddress, String cookieHeader,
                                 String authHeader) throws Exception {
        String pathOnly = stripQuery(path);
        if (!pathOnly.startsWith("/api/overlink/")) return false;

        // Anything not on the v1 surface is a version the phone should not have
        // called. 404 rather than a redirect, so its degradation path fires.
        if (!pathOnly.startsWith(PREFIX + "/")) {
            sendError(out, 404, "unknown_endpoint", "No such Overlink endpoint");
            return true;
        }
        String route = pathOnly.substring(PREFIX.length());

        try {
            switch (route) {
                case "/status":
                    if (!method.equals("GET")) return methodNotAllowed(out);
                    return status(out);

                case "/config":
                    if (method.equals("POST")) return saveConfig(body, out);
                    if (method.equals("DELETE")) return clearConfig(out);
                    return methodNotAllowed(out);

                case "/pair/start":
                    if (!method.equals("POST")) return methodNotAllowed(out);
                    return pairStart(out);

                case "/pair/session":
                    if (!method.equals("GET")) return methodNotAllowed(out);
                    return pairSession(out);

                case "/pair/cancel":
                    if (!method.equals("POST")) return methodNotAllowed(out);
                    return pairCancel(body, out);

                case "/pair/claim":
                    if (!method.equals("GET")) return methodNotAllowed(out);
                    return pairClaim(path, out, clientAddress);

                case "/devices":
                    if (!method.equals("GET")) return methodNotAllowed(out);
                    return listDevices(out);

                case "/devices/register":
                    if (!method.equals("POST")) return methodNotAllowed(out);
                    return register(body, out, clientAddress, cookieHeader, authHeader);

                case "/events":
                    if (!method.equals("GET")) return methodNotAllowed(out);
                    return events(path, out, clientAddress);

                case "/events/stream":
                    // SSE is explicitly optional in §8. Say so distinctly rather
                    // than 404ing, so the phone can tell "not built" from "wrong
                    // URL" and fall back to the cursor feed above.
                    sendError(out, 501, "not_implemented",
                            "This build serves /events only; there is no SSE stream yet");
                    return true;

                default:
                    break;
            }

            // /devices/{deviceId}/revoke | /forget
            if (route.startsWith("/devices/")) {
                String rest = route.substring("/devices/".length());
                int slash = rest.lastIndexOf('/');
                if (slash > 0) {
                    String deviceId = urlDecode(rest.substring(0, slash));
                    String action = rest.substring(slash + 1);
                    if (action.equals("revoke") && method.equals("POST")) {
                        return revokeDevice(deviceId, out);
                    }
                    if (action.equals("forget") && method.equals("POST")) {
                        return forgetDevice(deviceId, out);
                    }
                }
            }

            sendError(out, 404, "unknown_endpoint", "No such Overlink endpoint");
            return true;
        } catch (Exception e) {
            log("unhandled error on " + route + ": " + e);
            sendError(out, 500, "internal_error", "Overlink request failed");
            return true;
        }
    }

    // ==================== OWNER-FACING SETUP (§4.1) ====================

    /**
     * Everything the pairing settings screen needs in one call. Deliberately
     * never returns the client secret — only whether one is stored.
     */
    private static boolean status(OutputStream out) throws Exception {
        CarIdentity car = CarIdentity.read();
        JSONObject resp = new JSONObject();

        resp.put("success", true);
        resp.put("schema", OverlinkConfig.SCHEMA);
        resp.put("car_version", appVersion());
        resp.put("port", CameraDaemon.HTTP_PORT);
        resp.put("configured", OverlinkConfig.isConfigured());
        resp.put("oauth_client_id", OverlinkConfig.clientId());
        resp.put("has_client_secret", !OverlinkConfig.clientSecret().isEmpty());
        resp.put("phone_tag", OverlinkConfig.phoneTag());
        resp.put("car_tag", OverlinkConfig.carTag());
        resp.put("share_device_token", OverlinkConfig.shareDeviceToken());
        resp.put("lan_pairing", OverlinkConfig.lanPairingEnabled());
        resp.put("car_name", OverlinkConfig.carName());
        resp.put("car_model", OverlinkConfig.carModel());
        resp.put("caps", new JSONArray(OverlinkPairingManager.capabilities()));
        resp.put("car", car.toJson());
        // Nobody wants to transcribe JSON off a car's screen — the screen offers
        // this as copy-to-clipboard and as its own QR.
        resp.put("acl_grant", OverlinkConfig.aclGrant(CameraDaemon.HTTP_PORT));
        resp.put("device_count", DeviceRegistry.activeCount());
        resp.put("lan_ip", nullable(LanAddress.privateAddress()));

        // An untagged car cannot be named as a grant destination, and that is the
        // most common first-run stumble — surface it before pairing, not after.
        if (car.isRunning() && !car.tagged) {
            resp.put("warning", "car_untagged");
        }

        HttpResponse.sendJson(out, resp.toString());
        return true;
    }

    private static boolean saveConfig(String body, OutputStream out) throws Exception {
        JSONObject req = parseBody(body);
        if (req == null) {
            sendError(out, 400, "bad_request", "Expected a JSON body");
            return true;
        }

        String clientId = req.has("oauth_client_id") ? req.optString("oauth_client_id", "") : null;
        // A null secret leaves the stored one alone, so the screen can re-save
        // preferences without ever reading the secret back out.
        String clientSecret = req.has("oauth_client_secret")
                ? req.optString("oauth_client_secret", "") : null;
        if (clientSecret != null && clientSecret.isEmpty()) clientSecret = null;

        String phoneTag = req.has("phone_tag") ? req.optString("phone_tag", "") : null;
        if (phoneTag != null && !OverlinkConfig.isValidTag(phoneTag.trim())) {
            sendError(out, 400, "bad_tag",
                    "Tags must look like tag:overdrive-phone (lowercase letters, digits, hyphens)");
            return true;
        }
        String carTag = req.has("car_tag") ? req.optString("car_tag", "") : null;
        if (carTag != null && !OverlinkConfig.isValidTag(carTag.trim())) {
            sendError(out, 400, "bad_tag",
                    "Tags must look like tag:overdrive-car (lowercase letters, digits, hyphens)");
            return true;
        }

        boolean ok = true;
        if (clientId != null || clientSecret != null) {
            ok = OverlinkConfig.setCredentials(clientId, clientSecret);
        }
        ok = OverlinkConfig.setPreferences(
                phoneTag,
                carTag,
                req.has("share_device_token") ? Boolean.valueOf(req.optBoolean("share_device_token", true)) : null,
                req.has("lan_pairing") ? Boolean.valueOf(req.optBoolean("lan_pairing", false)) : null,
                req.has("car_name") ? req.optString("car_name", "") : null,
                req.has("car_model") ? req.optString("car_model", "") : null) && ok;

        if (!ok) {
            sendError(out, 500, "persist_failed", "Could not save pairing settings");
            return true;
        }
        return status(out);
    }

    private static boolean clearConfig(OutputStream out) throws Exception {
        // Worth restating in the UI, because it genuinely surprises people:
        // forgetting the OAuth client does NOT deauthorize already-paired
        // phones. It only stops new ones being paired.
        OverlinkPairingManager.cancel("OAuth client removed");
        boolean ok = OverlinkConfig.clearCredentials();
        JSONObject resp = new JSONObject();
        resp.put("success", ok);
        resp.put("note", "Already-paired phones keep their tailnet access. "
                + "Revoke them individually to cut it.");
        HttpResponse.sendJson(out, resp.toString());
        return true;
    }

    // ==================== PAIRING (§4.2–§4.4) ====================

    private static boolean pairStart(OutputStream out) throws Exception {
        OverlinkPairingManager.Session s;
        try {
            s = OverlinkPairingManager.start();
        } catch (OverlinkPairingManager.PairingException e) {
            // §11.6: each failure distinct, each with its own action. The reason
            // code is what the screen switches on.
            int code = "not_configured".equals(e.reason) ? 409
                     : "bad_credentials".equals(e.reason) ? 502
                     : "offline".equals(e.reason) ? 503
                     : "car_not_on_tailnet".equals(e.reason) ? 409
                     : "clock_skew".equals(e.reason) ? 409
                     : 502;
            sendError(out, code, e.reason, e.getMessage());
            return true;
        }
        HttpResponse.sendJson(out, sessionJson(s, true).toString());
        return true;
    }

    private static boolean pairSession(OutputStream out) throws Exception {
        OverlinkPairingManager.Session s = OverlinkPairingManager.active();
        if (s == null) {
            JSONObject resp = new JSONObject();
            resp.put("success", true);
            resp.put("state", "idle");
            HttpResponse.sendJson(out, resp.toString());
            return true;
        }
        HttpResponse.sendJson(out, sessionJson(s, false).toString());
        return true;
    }

    private static boolean pairCancel(String body, OutputStream out) throws Exception {
        JSONObject req = parseBody(body);
        String why = req != null ? req.optString("reason", "cancelled") : "cancelled";
        OverlinkPairingManager.cancel(why);
        JSONObject resp = new JSONObject();
        resp.put("success", true);
        resp.put("state", "idle");
        HttpResponse.sendJson(out, resp.toString());
        return true;
    }

    /**
     * Serialise a session for the pairing screen.
     *
     * @param includeSecrets true only on the response to {@code /pair/start},
     *                       which is the one place the QR URI has to cross a
     *                       process boundary. Polls get the countdown and state
     *                       but never re-send the key.
     */
    private static JSONObject sessionJson(OverlinkPairingManager.Session s, boolean includeSecrets)
            throws Exception {
        JSONObject resp = new JSONObject();
        resp.put("success", true);
        resp.put("state", s.state().name().toLowerCase(java.util.Locale.US));
        resp.put("nonce_hint", s.nonce.length() > 6 ? s.nonce.substring(0, 6) : "");
        resp.put("issued_at", s.issuedAt);
        resp.put("expires_at", s.expiresAt);
        resp.put("remaining_seconds", OverlinkPairingManager.remainingSeconds(s));
        resp.put("ttl_seconds", OverlinkPairingManager.PAIRING_TTL_SECONDS);
        resp.put("tag", s.tag);
        resp.put("lan_pairing", s.claimToken != null);

        if (includeSecrets) {
            resp.put("uri", s.uri);
            String lanUri = OverlinkPairingManager.buildLanUri(s);
            if (lanUri != null) resp.put("lan_uri", lanUri);
        }
        if (s.state() == OverlinkPairingManager.State.CONSUMED) {
            JSONObject row = DeviceRegistry.find(s.consumedBy());
            if (row != null) resp.put("paired_device", row);
        }
        return resp;
    }

    // ==================== LOCAL-NETWORK PAIRING (§4.6) ====================

    /**
     * {@code GET /pair/claim?t=<token>&nonce=<nonce>}
     *
     * <p>The one endpoint that must be reachable off-tailnet, because the tunnel
     * is not up yet. Guarded by a single-use token, rate-limited on the same
     * limiter as {@code /auth/token}, and restricted to private sources.
     */
    private static boolean pairClaim(String path, OutputStream out, SocketAddress clientAddress)
            throws Exception {
        if (!OverlinkConfig.lanPairingEnabled()) {
            sendError(out, 404, "not_enabled", "Local-network pairing is turned off on this car");
            return true;
        }
        // Serve the LAN and loopback only; a routable source has no business here.
        if (!LanAddress.isLocalNetwork(clientAddress) && !LanAddress.isTailnetPeer(clientAddress)) {
            sendError(out, 403, "not_local", "This endpoint is only served on the local network");
            return true;
        }

        // A guessable token on an unauthenticated LAN endpoint deserves the same
        // protection as the login endpoint, so it shares that bucket namespace.
        String identity = "overlink-claim:" + String.valueOf(LanAddress.extractIp(clientAddress));
        String limited = AuthApiHandler.checkRateLimitFor(identity);
        if (limited != null) {
            sendError(out, 429, "rate_limited", limited);
            return true;
        }

        Map<String, String> q = parseQuery(path);
        String token = q.get("t");
        String nonce = q.get("nonce");
        if (isBlank(token) || isBlank(nonce)) {
            sendError(out, 400, "bad_request", "Missing t or nonce");
            return true;
        }

        JSONObject payload = OverlinkPairingManager.claim(token, nonce);
        if (payload == null) {
            // 410 covers wrong / already used / expired as one indistinguishable
            // case, which is also what the phone shows the user.
            sendError(out, 410, "claim_unavailable",
                    "That code has already been used or has expired");
            return true;
        }
        AuthApiHandler.clearRateLimitFor(identity);

        String json = payload.toString();
        if (json.length() > MAX_CLAIM_BYTES) {
            log("claim payload unexpectedly large (" + json.length() + " bytes)");
            sendError(out, 500, "payload_too_large", "Pairing payload is too large to serve");
            return true;
        }
        HttpResponse.sendJson(out, json);
        return true;
    }

    // ==================== REGISTRATION (§5.1) ====================

    /**
     * {@code POST /devices/register} — called by the phone over the tunnel, once,
     * as soon as its node reaches {@code Running}.
     *
     * <p>Accepts <b>either</b> a valid {@code byd_session} JWT <b>or</b> a valid,
     * unconsumed, unexpired nonce. Both are sufficient on their own: the nonce is
     * single-use, expires in 300 seconds and only travels over the tunnel, so it
     * is a real credential in its own right — and it has to be, because a car that
     * omits {@code dt} leaves the phone with no session at registration time.
     * Requiring the JWT alone would make the registry unavailable to exactly the
     * setups that need it most.
     */
    private static boolean register(String body, OutputStream out, SocketAddress clientAddress,
                                    String cookieHeader, String authHeader) throws Exception {
        if (!isTrustedTunnelSource(clientAddress)) {
            sendError(out, 403, "not_tunnel",
                    "Registration is only accepted over the tunnel");
            return true;
        }

        JSONObject req = parseBody(body);
        if (req == null) {
            sendError(out, 400, "bad_request", "Expected a JSON body");
            return true;
        }

        String deviceId = req.optString("device_id", "").trim();
        if (deviceId.isEmpty() || deviceId.length() > DeviceRegistry.MAX_FIELD_LEN) {
            sendError(out, 400, "bad_device_id", "device_id is required");
            return true;
        }
        String nonce = req.optString("nonce", "").trim();

        boolean hasJwt = hasValidJwt(cookieHeader, authHeader);
        boolean nonceOk = !nonce.isEmpty() && OverlinkPairingManager.consumeNonce(nonce, deviceId);
        if (!hasJwt && !nonceOk) {
            // A nonce that was never issued, already consumed by a different
            // device, or expired lands here — which is what makes the replay
            // test meaningful.
            sendError(out, 401, "unauthorized",
                    "Registration needs a valid session or an unused pairing code");
            return true;
        }

        String nodeId = req.optString("node_id", "").trim();
        String nodeIp = req.optString("node_ip", "").trim();
        JSONObject pushRoute = req.optJSONObject("push_route");   // always null in v1

        JSONObject row = DeviceRegistry.upsert(
                deviceId,
                req.optString("label", ""),
                req.optString("platform", ""),
                req.optString("os_version", ""),
                req.optString("app_version", ""),
                nodeId,
                nodeIp,
                pushRoute);

        if (row == null) {
            sendError(out, 500, "persist_failed", "Could not record this device");
            return true;
        }

        JSONObject resp = new JSONObject();
        resp.put("car_version", appVersion());
        // Authoritative: the QR is a snapshot from pairing time and the car may
        // have been updated since, so the phone overwrites its stored copy.
        resp.put("caps", new JSONArray(OverlinkPairingManager.capabilities()));

        attachNodeFacts(resp, nodeId, nodeIp);

        log("registered " + deviceId + " (" + row.optString("label", "?") + ")"
                + " node=" + (nodeId.isEmpty() ? "?" : nodeId)
                + " via=" + (nonceOk ? "nonce" : "jwt"));
        HttpResponse.sendJson(out, 201, resp.toString());
        return true;
    }

    /**
     * §4.5 — report what actually registered.
     *
     * <p>This is the highest-value part of registration: it converts a silent,
     * delayed-onset failure into a message at pair time. The phone cannot see its
     * own ephemerality ({@code tsnet} does not expose it); the car can, because
     * it holds the API credentials.
     *
     * <p>If the lookup fails the fields are simply omitted — the device still
     * registered, and the phone treats missing fields as "unknown" rather than as
     * a problem.
     */
    private static void attachNodeFacts(JSONObject resp, String nodeId, String nodeIp) {
        if (nodeId.isEmpty() && nodeIp.isEmpty()) return;
        TailscaleApiClient api = TailscaleApiClient.fromConfig();
        if (api == null) return;
        try {
            TailscaleApiClient.DeviceFacts facts = api.findDevice(nodeId, nodeIp);
            if (facts == null) {
                log("registered node " + nodeId + " not found in the tailnet device list");
                return;
            }
            // Phone will be evicted after ~30-60 min offline; pairing dies days later.
            resp.put("node_ephemeral", facts.ephemeral);
            // Tagged devices should not expire — an expiry means the tag did not apply.
            resp.put("node_key_expiry", facts.keyExpiry == null
                    ? JSONObject.NULL : facts.keyExpiry);
            // What control actually applied, which is not necessarily what was asked for.
            resp.put("node_tags", new JSONArray(facts.tags));
        } catch (Exception e) {
            log("node fact lookup failed (non-fatal): " + e.getMessage());
        }
    }

    // ==================== DEVICE LIST + REVOCATION (§5.3) ====================

    private static boolean listDevices(OutputStream out) throws Exception {
        JSONObject resp = new JSONObject();
        resp.put("success", true);
        resp.put("devices", DeviceRegistry.list());
        resp.put("configured", OverlinkConfig.isConfigured());
        HttpResponse.sendJson(out, resp.toString());
        return true;
    }

    private static boolean revokeDevice(String deviceId, OutputStream out) throws Exception {
        DeviceRegistry.RevokeResult r = DeviceRegistry.revoke(deviceId);
        JSONObject resp = new JSONObject();
        resp.put("success", r.ok);
        if (!r.ok) {
            // Both halves stay consistent on failure: the row is not marked
            // either. A half-applied revocation the UI claims succeeded is worse
            // than a visible error.
            resp.put("error", r.error);
            resp.put("missing_node_id", r.missingNodeId);
            HttpResponse.sendJson(out, 502, resp.toString());
            return true;
        }
        resp.put("devices", DeviceRegistry.list());
        HttpResponse.sendJson(out, resp.toString());
        return true;
    }

    private static boolean forgetDevice(String deviceId, OutputStream out) throws Exception {
        JSONObject row = DeviceRegistry.find(deviceId);
        if (row != null && !row.optBoolean("revoked", false)) {
            // Dropping a live row without deleting the node is precisely the
            // half-revocation §5.3 forbids: the phone keeps tailnet access and
            // silently re-registers on the next pair.
            sendError(out, 409, "not_revoked",
                    "Revoke this device before forgetting it, or it keeps its tailnet access");
            return true;
        }
        boolean ok = DeviceRegistry.forget(deviceId);
        JSONObject resp = new JSONObject();
        resp.put("success", ok);
        resp.put("devices", DeviceRegistry.list());
        HttpResponse.sendJson(out, resp.toString());
        return true;
    }

    // ==================== EVENT STREAM (§8) ====================

    /**
     * {@code GET /events?since=<id>&limit=<n>} — the canonical event schema,
     * layered over the existing notification log rather than built beside it.
     *
     * <p>{@code id} is stable and monotonic per car (an H2 {@code IDENTITY}
     * column), which is what makes it usable as the deduplication and backfill
     * key: the phone keeps a cursor and asks for everything newer on foreground,
     * so the event list is correct regardless of whether push ever worked.
     */
    private static boolean events(String path, OutputStream out, SocketAddress clientAddress)
            throws Exception {
        if (!isTrustedTunnelSource(clientAddress)) {
            sendError(out, 403, "not_tunnel", "The event stream is only served over the tunnel");
            return true;
        }
        NotificationStore store = NotificationStore.getInstanceOrNull();
        if (store == null) {
            sendError(out, 503, "log_unavailable", "The notification log is not running");
            return true;
        }

        Map<String, String> q = parseQuery(path);
        long since = parseLong(q.get("since"), 0L);
        int limit = (int) parseLong(q.get("limit"), DEFAULT_EVENT_LIMIT);
        limit = Math.max(1, Math.min(limit, MAX_EVENT_LIMIT));

        JSONArray rows = store.listSince(since, limit);
        JSONArray events = new JSONArray();
        long cursor = since;
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.optJSONObject(i);
            if (row == null) continue;
            events.put(toEvent(row));
            cursor = Math.max(cursor, row.optLong("id", cursor));
        }

        JSONObject resp = new JSONObject();
        resp.put("success", true);
        resp.put("events", events);
        resp.put("cursor", cursor);
        // The phone pages until this goes false rather than guessing from length.
        resp.put("has_more", rows.length() == limit);
        HttpResponse.sendJson(out, resp.toString());
        return true;
    }

    /** Map one notification-log row onto the canonical event schema. */
    private static JSONObject toEvent(JSONObject row) throws Exception {
        JSONObject e = new JSONObject();
        long id = row.optLong("id", 0);
        e.put("id", id);
        // The log stores epoch-ms; the canonical schema is epoch-seconds.
        e.put("ts", row.optLong("ts", 0) / 1000L);
        e.put("type", row.optString("category", "unknown"));
        e.put("severity", row.optString("severity", "info"));

        JSONObject data = row.optJSONObject("data");
        String camera = data != null ? data.optString("camera", "") : "";
        if (!camera.isEmpty()) e.put("camera", camera);

        // Thumbnails are a PATH, fetched over the tunnel on demand — never
        // embedded, and never carried in a push payload. The signed-token
        // mechanism this reuses was built for exactly this.
        String filename = data != null ? data.optString("filename", "") : "";
        if (!filename.isEmpty()) {
            String token = AuthManager.signThumbToken(filename, THUMB_TOKEN_TTL_SEC);
            if (token != null) {
                e.put("thumbnail_path", "/thumb/" + urlEncode(filename) + "?t=" + token);
            }
        }

        String title = row.optString("title", "");
        String bodyText = row.optString("body", "");
        e.put("summary", bodyText.isEmpty() ? title : title + " — " + bodyText);
        e.put("deep_link", "overdrive://event/" + id);
        return e;
    }

    // ==================== SOURCE CLASSIFICATION ====================

    /**
     * True when a request may be treated as arriving over the tunnel.
     *
     * <p>Accepts a Tailscale peer address, and also loopback because
     * {@code --tun userspace-networking} re-originates inbound tailnet
     * connections into loopback (see the class comment). Refuses an ordinary LAN
     * or routable source, which is the distinction §11.2 actually cares about:
     * the tailnet is the authenticated channel, the LAN is not.
     */
    private static boolean isTrustedTunnelSource(SocketAddress clientAddress) {
        if (clientAddress == null) return false;
        return LanAddress.isTailnetPeer(clientAddress) || LanAddress.isLoopback(clientAddress);
    }

    private static boolean hasValidJwt(String cookieHeader, String authHeader) {
        String jwt = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7).trim();
        }
        if ((jwt == null || jwt.isEmpty()) && cookieHeader != null) {
            for (String cookie : cookieHeader.split(";")) {
                String[] parts = cookie.trim().split("=", 2);
                if (parts.length == 2 && parts[0].trim().equals("byd_session")) {
                    jwt = parts[1].trim();
                    break;
                }
            }
        }
        if (jwt == null || jwt.isEmpty()) return false;
        try {
            AuthManager.JwtValidation v = AuthManager.validateJwt(jwt);
            return v != null && v.valid;
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== PLUMBING ====================

    private static boolean methodNotAllowed(OutputStream out) throws Exception {
        sendError(out, 405, "method_not_allowed", "Method not allowed");
        return true;
    }

    private static void sendError(OutputStream out, int status, String reason, String message)
            throws Exception {
        JSONObject j = new JSONObject();
        try {
            j.put("success", false);
            j.put("reason", reason);
            j.put("error", message);
        } catch (Exception ignored) {
            // JSONObject.put only throws on a null key.
        }
        HttpResponse.sendJson(out, status, j.toString());
    }

    private static JSONObject parseBody(String body) {
        if (body == null || body.trim().isEmpty()) return null;
        try {
            return new JSONObject(body);
        } catch (Exception e) {
            return null;
        }
    }

    private static String appVersion() {
        try {
            return com.overdrive.app.BuildConfig.VERSION_NAME;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private static Object nullable(String s) {
        return (s == null || s.isEmpty()) ? JSONObject.NULL : s;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String stripQuery(String path) {
        int q = path.indexOf('?');
        return q < 0 ? path : path.substring(0, q);
    }

    private static Map<String, String> parseQuery(String path) {
        Map<String, String> map = new java.util.HashMap<>();
        int q = path.indexOf('?');
        if (q < 0 || q == path.length() - 1) return map;
        for (String pair : path.substring(q + 1).split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            map.put(urlDecode(pair.substring(0, eq)), urlDecode(pair.substring(eq + 1)));
        }
        return map;
    }

    private static long parseLong(String s, long fallback) {
        if (s == null || s.isEmpty()) return fallback;
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static void log(String message) {
        CameraDaemon.log("OVERLINK: " + message);
    }
}
