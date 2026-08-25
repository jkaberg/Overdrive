package com.overdrive.app.overlink;

import com.overdrive.app.config.UnifiedConfigManager;
import com.overdrive.app.daemon.CameraDaemon;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Persistent state for the Overlink companion-app integration.
 *
 * <p>Everything lives in the {@code "overlink"} section of the unified config
 * ({@code /data/local/tmp/overdrive_config.json}), alongside {@code automation},
 * {@code camera}, {@code recording}, {@code surveillance} and {@code telegram}.
 *
 * <h3>Why the unified config and not Android Keystore</h3>
 * The Overlink spec (§4.1) asks for the OAuth client secret in
 * AndroidKeyStore-backed storage, "following {@code auth/PinManager.java}".
 * PinManager does not do that, and neither can this: {@link CameraDaemon} is a
 * standalone {@code app_process} JVM running as the shell UID (2000), while the
 * settings UI runs as the app UID. AndroidKeyStore and EncryptedSharedPreferences
 * are both per-UID, so a secret written by the UI would be unreadable by the
 * daemon that has to use it — §4.5's device lookup and §5.3's revocation are
 * both served from the daemon. The unified config is this codebase's established
 * cross-UID credential store for exactly that reason; it already holds
 * {@link com.overdrive.app.auth.AuthManager}'s device secret (full dashboard
 * access), PinManager's PIN hash and the Telegram bot token.
 *
 * <p>What the spec's concern buys instead is applied at the blast-radius level:
 * the client secret never leaves this process boundary (never returned by an
 * API, never placed in a QR, never logged), and every key it mints is
 * single-use, tagged, 300s-lived and deleted on consumption (§4.2).
 *
 * <h3>Survives reinstall and OTA (§5.4)</h3>
 * The unified config is outside app-private storage, so the device registry
 * survives an OverDrive uninstall/reinstall and a userdata-preserving OTA. Only
 * a factory reset clears it — and even then nothing needs re-scanning, because
 * the phone's tailnet identity is independent of the car and it re-registers on
 * next start.
 */
public final class OverlinkConfig {

    public static final String SECTION = "overlink";

    /** Bump only for a breaking shape change; readers tolerate unknown keys. */
    public static final int SCHEMA = 1;

    public static final String DEFAULT_PHONE_TAG = "tag:overdrive-phone";
    public static final String DEFAULT_CAR_TAG = "tag:overdrive-car";

    private static final String KEY_SCHEMA = "schema";
    private static final String KEY_CLIENT_ID = "oauthClientId";
    private static final String KEY_CLIENT_SECRET = "oauthClientSecret";
    private static final String KEY_PHONE_TAG = "phoneTag";
    private static final String KEY_CAR_TAG = "carTag";
    private static final String KEY_SHARE_TOKEN = "shareDeviceToken";
    private static final String KEY_LAN_PAIRING = "lanPairing";
    private static final String KEY_CAR_NAME = "carName";
    private static final String KEY_CAR_MODEL = "carModel";
    private static final String KEY_DEVICES = "devices";

    private OverlinkConfig() {}

    // ==================== SECTION ACCESS ====================

    public static JSONObject section() {
        try {
            JSONObject s = UnifiedConfigManager.loadConfig().optJSONObject(SECTION);
            return s != null ? s : new JSONObject();
        } catch (Exception e) {
            log("section read failed: " + e.getMessage());
            return new JSONObject();
        }
    }

    /** Re-read from disk, bypassing the cache. Used before a read-modify-write. */
    public static JSONObject sectionFresh() {
        try {
            JSONObject s = UnifiedConfigManager.forceReload().optJSONObject(SECTION);
            return s != null ? s : new JSONObject();
        } catch (Exception e) {
            log("section reload failed: " + e.getMessage());
            return section();
        }
    }

    /**
     * Merge {@code delta} into the section. UnifiedConfigManager merges per key,
     * so a caller may write a single field without reading the rest first — but
     * a whole-array key like {@code devices} is replaced wholesale.
     */
    private static boolean write(JSONObject delta) {
        try {
            delta.put(KEY_SCHEMA, SCHEMA);
            return UnifiedConfigManager.updateSection(SECTION, delta);
        } catch (Exception e) {
            log("section write failed: " + e.getMessage());
            return false;
        }
    }

    // ==================== OAUTH CREDENTIALS (§4.1) ====================

    public static String clientId() {
        return section().optString(KEY_CLIENT_ID, "").trim();
    }

    /**
     * The OAuth client secret. Callers must treat the return value as
     * write-only: never echo it into an HTTP response, a QR payload or a log line.
     */
    public static String clientSecret() {
        return section().optString(KEY_CLIENT_SECRET, "").trim();
    }

    public static boolean isConfigured() {
        return !clientId().isEmpty() && !clientSecret().isEmpty();
    }

    /**
     * Persist owner-supplied credentials. A null {@code clientSecret} leaves the
     * stored secret untouched, so the settings screen can re-save the other
     * fields without ever reading the secret back out.
     */
    public static boolean setCredentials(String clientId, String clientSecret) {
        JSONObject delta = new JSONObject();
        try {
            if (clientId != null) delta.put(KEY_CLIENT_ID, clientId.trim());
            if (clientSecret != null) delta.put(KEY_CLIENT_SECRET, clientSecret.trim());
        } catch (Exception e) {
            return false;
        }
        return write(delta);
    }

    public static boolean clearCredentials() {
        JSONObject delta = new JSONObject();
        try {
            delta.put(KEY_CLIENT_ID, "");
            delta.put(KEY_CLIENT_SECRET, "");
        } catch (Exception e) {
            return false;
        }
        return write(delta);
    }

    // ==================== PAIRING PREFERENCES ====================

    /** Tag applied to phone nodes. Must satisfy the phone's own regex (§4.4). */
    public static String phoneTag() {
        String t = section().optString(KEY_PHONE_TAG, "").trim();
        return isValidTag(t) ? t : DEFAULT_PHONE_TAG;
    }

    /** Tag the car's node is expected to carry — used to render the ACL grant (§9.4). */
    public static String carTag() {
        String t = section().optString(KEY_CAR_TAG, "").trim();
        return isValidTag(t) ? t : DEFAULT_CAR_TAG;
    }

    /**
     * Whether the pairing QR carries OverDrive's device token (§6). Defaults on:
     * without it the user meets a PIN prompt on first load and every 30 days
     * after, which is the friction Overlink exists to remove.
     */
    public static boolean shareDeviceToken() {
        return section().optBoolean(KEY_SHARE_TOKEN, true);
    }

    /** Whether the §4.6 local-network claim endpoint is offered. Off by default. */
    public static boolean lanPairingEnabled() {
        return section().optBoolean(KEY_LAN_PAIRING, false);
    }

    /** Display name shown on the phone; falls back to the car's MagicDNS label. */
    public static String carName() {
        return section().optString(KEY_CAR_NAME, "").trim();
    }

    /** One of atto3/seal/dolphin/tang — selects the phone's accent colour (§4.4). */
    public static String carModel() {
        return section().optString(KEY_CAR_MODEL, "").trim();
    }

    public static boolean setPreferences(String phoneTag, String carTag,
                                         Boolean shareDeviceToken, Boolean lanPairing,
                                         String carName, String carModel) {
        JSONObject delta = new JSONObject();
        try {
            if (phoneTag != null && isValidTag(phoneTag.trim())) delta.put(KEY_PHONE_TAG, phoneTag.trim());
            if (carTag != null && isValidTag(carTag.trim())) delta.put(KEY_CAR_TAG, carTag.trim());
            if (shareDeviceToken != null) delta.put(KEY_SHARE_TOKEN, shareDeviceToken.booleanValue());
            if (lanPairing != null) delta.put(KEY_LAN_PAIRING, lanPairing.booleanValue());
            if (carName != null) delta.put(KEY_CAR_NAME, carName.trim());
            if (carModel != null) delta.put(KEY_CAR_MODEL, carModel.trim());
        } catch (Exception e) {
            return false;
        }
        return delta.length() == 0 || write(delta);
    }

    /** {@code ^tag:[a-z0-9][a-z0-9-]{0,62}$} — the phone rejects anything else (§4.4). */
    public static boolean isValidTag(String tag) {
        return tag != null && tag.matches("^tag:[a-z0-9][a-z0-9-]{0,62}$");
    }

    // ==================== DEVICE REGISTRY (§5.2) ====================

    public static JSONArray devices() {
        JSONArray a = section().optJSONArray(KEY_DEVICES);
        return a != null ? a : new JSONArray();
    }

    /** Replaces the whole {@code devices} array. Callers hold {@link DeviceRegistry}'s lock. */
    static boolean writeDevices(JSONArray devices) {
        JSONObject delta = new JSONObject();
        try {
            delta.put(KEY_DEVICES, devices);
        } catch (Exception e) {
            return false;
        }
        return write(delta);
    }

    /** Fresh read of the devices array, for the read-modify-write path. */
    static JSONArray devicesFresh() {
        JSONArray a = sectionFresh().optJSONArray(KEY_DEVICES);
        return a != null ? a : new JSONArray();
    }

    // ==================== ACL GRANT (§9.4) ====================

    /**
     * The tailnet policy block the owner pastes into the Tailscale admin console,
     * with the configured tags substituted so it can be copied verbatim. This
     * grant is the real security boundary — note what it does <em>not</em> give
     * phones: no exit-node use, no subnet routes, no access to any other host.
     */
    public static String aclGrant(int dashboardPort) {
        String phone = phoneTag();
        String car = carTag();
        return "{\n"
             + "  \"tagOwners\": {\n"
             + "    \"" + phone + "\": [\"autogroup:admin\"],\n"
             + "    \"" + car + "\": [\"autogroup:admin\"]\n"
             + "  },\n"
             + "  \"grants\": [\n"
             + "    {\n"
             + "      \"src\": [\"" + phone + "\"],\n"
             + "      \"dst\": [\"" + car + "\"],\n"
             + "      \"ip\": [\"tcp:" + dashboardPort + "\"]\n"
             + "    }\n"
             + "  ]\n"
             + "}";
    }

    static void log(String message) {
        CameraDaemon.log("OVERLINK: " + message);
    }
}
