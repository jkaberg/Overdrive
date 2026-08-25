package com.overdrive.app.overlink;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The paired-phone registry (§5.2), stored in the {@code overlink} config section.
 *
 * <p>Rows are keyed on the client-generated, install-stable {@code device_id}, so
 * re-pairing the same phone updates its row rather than leaving a ghost behind.
 * {@code first_paired} is preserved across updates.
 *
 * <p>{@code node_id} is the phone's own StableNodeID, supplied directly in the
 * registration payload rather than inferred from the connection's source address
 * — inference works on the first registration and stops working the moment the
 * phone's address changes. It is what makes {@link #revoke one-action revocation}
 * possible at all: without it, revoking can only set a flag while the phone keeps
 * its tailnet access.
 */
public final class DeviceRegistry {

    /** Guards the read-modify-write cycle against two concurrent registrations. */
    private static final Object LOCK = new Object();

    /**
     * Cap on stored rows. Far above any plausible household; keeps a hostile or
     * looping client from growing the config file without bound.
     */
    private static final int MAX_DEVICES = 64;

    public static final int MAX_FIELD_LEN = 128;

    private DeviceRegistry() {}

    // ==================== READ ====================

    /** All rows, newest activity first. Never null. */
    public static JSONArray list() {
        JSONArray devices = OverlinkConfig.devices();
        JSONArray sorted = new JSONArray();
        java.util.List<JSONObject> rows = new java.util.ArrayList<>();
        for (int i = 0; i < devices.length(); i++) {
            JSONObject d = devices.optJSONObject(i);
            if (d != null) rows.add(d);
        }
        rows.sort((a, b) -> Long.compare(b.optLong("last_seen", 0), a.optLong("last_seen", 0)));
        for (JSONObject r : rows) sorted.put(r);
        return sorted;
    }

    public static JSONObject find(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) return null;
        JSONArray devices = OverlinkConfig.devices();
        for (int i = 0; i < devices.length(); i++) {
            JSONObject d = devices.optJSONObject(i);
            if (d != null && deviceId.equals(d.optString("device_id", null))) return d;
        }
        return null;
    }

    public static int activeCount() {
        JSONArray devices = OverlinkConfig.devices();
        int n = 0;
        for (int i = 0; i < devices.length(); i++) {
            JSONObject d = devices.optJSONObject(i);
            if (d != null && !d.optBoolean("revoked", false)) n++;
        }
        return n;
    }

    // ==================== WRITE ====================

    /**
     * Insert or update a row from a registration payload (§5.1).
     *
     * @return the stored row, or null when the write failed.
     */
    public static JSONObject upsert(String deviceId, String label, String platform,
                                    String osVersion, String appVersion, String nodeId,
                                    String nodeIp, JSONObject pushRoute) {
        if (deviceId == null || deviceId.isEmpty()) return null;
        long now = System.currentTimeMillis() / 1000L;

        synchronized (LOCK) {
            JSONArray devices = OverlinkConfig.devicesFresh();
            JSONArray next = new JSONArray();
            JSONObject stored = null;

            for (int i = 0; i < devices.length(); i++) {
                JSONObject d = devices.optJSONObject(i);
                if (d == null) continue;
                if (deviceId.equals(d.optString("device_id", null))) {
                    stored = d;               // keep the original first_paired
                } else {
                    next.put(d);
                }
            }

            try {
                JSONObject row = stored != null ? stored : new JSONObject();
                if (stored == null) row.put("first_paired", now);
                row.put("device_id", deviceId);
                row.put("label", clamp(label));
                row.put("platform", clamp(platform));
                row.put("os_version", clamp(osVersion));
                row.put("app_version", clamp(appVersion));
                row.put("node_id", clamp(nodeId));
                row.put("node_ip", clamp(nodeIp));
                row.put("last_seen", now);
                // Re-registering an explicitly revoked phone un-revokes it: the
                // owner had to display a fresh QR for that to be possible.
                row.put("revoked", false);
                // Always null in v1. Stored anyway so notifications can be turned
                // on later without asking every existing user to re-scan (§5.1).
                row.put("push_route", pushRoute != null ? pushRoute : JSONObject.NULL);

                next.put(row);
                trim(next);

                if (!OverlinkConfig.writeDevices(next)) {
                    OverlinkConfig.log("registry write failed for " + deviceId);
                    return null;
                }
                return row;
            } catch (Exception e) {
                OverlinkConfig.log("registry upsert failed: " + e.getMessage());
                return null;
            }
        }
    }

    /** Bump {@code last_seen} without touching anything else. Best-effort. */
    public static void touch(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) return;
        synchronized (LOCK) {
            JSONArray devices = OverlinkConfig.devicesFresh();
            boolean changed = false;
            for (int i = 0; i < devices.length(); i++) {
                JSONObject d = devices.optJSONObject(i);
                if (d != null && deviceId.equals(d.optString("device_id", null))) {
                    try {
                        d.put("last_seen", System.currentTimeMillis() / 1000L);
                        changed = true;
                    } catch (Exception ignored) {
                        // Non-fatal: last_seen is cosmetic.
                    }
                    break;
                }
            }
            if (changed) OverlinkConfig.writeDevices(devices);
        }
    }

    // ==================== REVOCATION (§5.3) ====================

    /** Outcome of a revoke attempt, so the UI can report exactly what happened. */
    public static final class RevokeResult {
        public final boolean ok;
        public final String error;
        /** True when the row existed but carried no node ID to delete. */
        public final boolean missingNodeId;

        RevokeResult(boolean ok, String error, boolean missingNodeId) {
            this.ok = ok;
            this.error = error;
            this.missingNodeId = missingNodeId;
        }
    }

    /**
     * Revoke a phone: mark the registry row <em>and</em> delete the tailnet node.
     * One action, both halves, always.
     *
     * <p>Registry-only revocation leaves a phone with working tailnet access;
     * tailnet-only deletion leaves a stale row that silently re-registers on the
     * next pair. So if the Tailscale call fails, the row is <em>not</em> marked
     * either — better a visible error than a half-applied revocation the UI
     * claims succeeded.
     *
     * <p>Note for the UI: revoking the OAuth client does not deauthorize
     * already-paired phones. It only stops new ones being paired.
     */
    public static RevokeResult revoke(String deviceId) {
        JSONObject row = find(deviceId);
        if (row == null) {
            return new RevokeResult(false, "No such paired device", false);
        }
        String nodeId = row.optString("node_id", "");

        TailscaleApiClient api = TailscaleApiClient.fromConfig();
        if (api == null) {
            return new RevokeResult(false,
                    "Phone pairing is not set up, so the tailnet node cannot be removed. "
                    + "Delete it in the Tailscale admin console, or add the OAuth client first.",
                    nodeId.isEmpty());
        }
        if (nodeId.isEmpty()) {
            return new RevokeResult(false,
                    "This device registered without a node ID, so its tailnet access cannot be "
                    + "removed from here. Delete it in the Tailscale admin console.",
                    true);
        }

        try {
            api.deleteDevice(nodeId);
        } catch (TailscaleApiClient.ApiException e) {
            OverlinkConfig.log("revoke failed for " + deviceId + ": " + e.getMessage());
            return new RevokeResult(false, e.getMessage(), false);
        }

        // The tailnet half succeeded — now, and only now, mark the row.
        synchronized (LOCK) {
            JSONArray devices = OverlinkConfig.devicesFresh();
            for (int i = 0; i < devices.length(); i++) {
                JSONObject d = devices.optJSONObject(i);
                if (d != null && deviceId.equals(d.optString("device_id", null))) {
                    try {
                        d.put("revoked", true);
                        d.put("revoked_at", System.currentTimeMillis() / 1000L);
                    } catch (Exception ignored) {
                        // Non-fatal: the tailnet node is already gone.
                    }
                    break;
                }
            }
            OverlinkConfig.writeDevices(devices);
        }
        return new RevokeResult(true, null, false);
    }

    /** Drop a revoked row entirely. Does not touch the tailnet — see {@link #revoke}. */
    public static boolean forget(String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) return false;
        synchronized (LOCK) {
            JSONArray devices = OverlinkConfig.devicesFresh();
            JSONArray next = new JSONArray();
            boolean removed = false;
            for (int i = 0; i < devices.length(); i++) {
                JSONObject d = devices.optJSONObject(i);
                if (d == null) continue;
                if (deviceId.equals(d.optString("device_id", null))) {
                    removed = true;
                } else {
                    next.put(d);
                }
            }
            return removed && OverlinkConfig.writeDevices(next);
        }
    }

    // ==================== PLUMBING ====================

    /** Drop the least recently seen revoked rows, then the oldest, down to the cap. */
    private static void trim(JSONArray devices) {
        if (devices.length() <= MAX_DEVICES) return;
        java.util.List<JSONObject> rows = new java.util.ArrayList<>();
        for (int i = 0; i < devices.length(); i++) {
            JSONObject d = devices.optJSONObject(i);
            if (d != null) rows.add(d);
        }
        rows.sort((a, b) -> {
            boolean ra = a.optBoolean("revoked", false);
            boolean rb = b.optBoolean("revoked", false);
            if (ra != rb) return ra ? 1 : -1;   // revoked rows go last
            return Long.compare(b.optLong("last_seen", 0), a.optLong("last_seen", 0));
        });
        while (devices.length() > 0) devices.remove(devices.length() - 1);
        for (int i = 0; i < Math.min(rows.size(), MAX_DEVICES); i++) devices.put(rows.get(i));
    }

    /** Bound every stored string so a hostile payload can't bloat the config. */
    private static String clamp(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.length() > MAX_FIELD_LEN ? t.substring(0, MAX_FIELD_LEN) : t;
    }
}
