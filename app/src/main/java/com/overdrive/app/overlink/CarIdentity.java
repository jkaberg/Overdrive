package com.overdrive.app.overlink;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * The car's own tailnet identity, read from {@code tailscale status --json} (§4.3).
 *
 * <p>No API call is needed for any of this — the CLI is already on disk and the
 * daemon runs as the shell UID that owns it, so this execs the binary directly
 * rather than going the long way round through
 * {@link com.overdrive.app.launcher.TailscaleLauncher}'s ADB executor (which
 * needs an Android {@code Context} the daemon JVM does not have).
 *
 * <p>Paths and the CLI socket mirror {@code TailscaleLauncher}'s constants; if
 * those move, these must move with them.
 */
public final class CarIdentity {

    private static final String TAILSCALE_HOME = "/data/local/tmp/.tailscale";
    private static final String TAILSCALE_BIN = TAILSCALE_HOME + "/tailscale";
    private static final String CLI_SOCKET = "127.0.0.1:8532";

    private static final long EXEC_TIMEOUT_SEC = 10;

    /** Tailscale's CGNAT v4 range and its ULA v6 prefix (§4.4 validation). */
    private static final String TS_V6_PREFIX = "fd7a:115c:a1e0";

    public final String nodeId;
    public final String tailscaleIp;
    /** MagicDNS name with the trailing dot stripped — the phone tolerates it, display does not. */
    public final String fqdn;
    public final String backendState;
    public final boolean tagged;
    public final JSONArray tags;

    private CarIdentity(String nodeId, String tailscaleIp, String fqdn,
                        String backendState, boolean tagged, JSONArray tags) {
        this.nodeId = nodeId;
        this.tailscaleIp = tailscaleIp;
        this.fqdn = fqdn;
        this.backendState = backendState;
        this.tagged = tagged;
        this.tags = tags;
    }

    /** True when the node has joined a tailnet and pairing may be offered. */
    public boolean isRunning() {
        return "Running".equals(backendState);
    }

    /** True when every field the QR requires is present and well-formed. */
    public boolean isComplete() {
        return isRunning()
                && nodeId != null && !nodeId.isEmpty()
                && tailscaleIp != null && isTailscaleAddress(tailscaleIp)
                && fqdn != null && !fqdn.isEmpty();
    }

    public JSONObject toJson() {
        JSONObject j = new JSONObject();
        try {
            j.put("node_id", nodeId == null ? JSONObject.NULL : nodeId);
            j.put("ts_ip", tailscaleIp == null ? JSONObject.NULL : tailscaleIp);
            j.put("fqdn", fqdn == null ? JSONObject.NULL : fqdn);
            j.put("backend_state", backendState == null ? "Unknown" : backendState);
            j.put("running", isRunning());
            j.put("complete", isComplete());
            // The most common first-run stumble: an untagged car cannot be named
            // as a grant destination, so pairing "works" and then nothing routes.
            j.put("tagged", tagged);
            j.put("tags", tags != null ? tags : new JSONArray());
        } catch (Exception ignored) {
            // JSONObject.put only throws on a null key; nothing to recover.
        }
        return j;
    }

    // ==================== READ ====================

    /** Runs the CLI and parses {@code Self}. Never returns null; check {@link #isRunning()}. */
    public static CarIdentity read() {
        String out = exec(TAILSCALE_BIN + " --socket " + CLI_SOCKET + " status --json");
        if (out == null || out.isEmpty()) {
            return new CarIdentity(null, null, null, "Unreachable", false, new JSONArray());
        }
        try {
            JSONObject root = new JSONObject(out);
            String backendState = root.optString("BackendState", "Unknown");
            JSONObject self = root.optJSONObject("Self");
            if (self == null) {
                return new CarIdentity(null, null, null, backendState, false, new JSONArray());
            }

            String nodeId = emptyToNull(self.optString("ID", ""));

            String ip = null;
            JSONArray ips = self.optJSONArray("TailscaleIPs");
            if (ips != null) {
                // Prefer the v4 CGNAT address; the phone accepts either.
                for (int i = 0; i < ips.length(); i++) {
                    String candidate = ips.optString(i, "");
                    if (isTailscaleAddress(candidate)) {
                        ip = candidate;
                        if (candidate.indexOf(':') < 0) break;
                    }
                }
            }

            // DNSName is fully qualified with a trailing dot.
            String fqdn = self.optString("DNSName", "");
            if (fqdn.endsWith(".")) fqdn = fqdn.substring(0, fqdn.length() - 1);
            fqdn = emptyToNull(fqdn);

            JSONArray tags = self.optJSONArray("Tags");
            if (tags == null) tags = new JSONArray();

            return new CarIdentity(nodeId, ip, fqdn, backendState, tags.length() > 0, tags);
        } catch (Exception e) {
            OverlinkConfig.log("status --json parse failed: " + e.getMessage());
            return new CarIdentity(null, null, null, "Unparseable", false, new JSONArray());
        }
    }

    /** The car's short MagicDNS label, used as a display name fallback. */
    public String shortName() {
        if (fqdn == null || fqdn.isEmpty()) return "OverDrive";
        int dot = fqdn.indexOf('.');
        return dot > 0 ? fqdn.substring(0, dot) : fqdn;
    }

    // ==================== VALIDATION ====================

    /** Must be inside {@code 100.64.0.0/10} or {@code fd7a:115c:a1e0::/48} (§4.4). */
    public static boolean isTailscaleAddress(String addr) {
        if (addr == null || addr.isEmpty()) return false;
        if (addr.indexOf(':') >= 0) {
            return addr.toLowerCase(java.util.Locale.US).startsWith(TS_V6_PREFIX);
        }
        String[] parts = addr.split("\\.");
        if (parts.length != 4) return false;
        try {
            int a = Integer.parseInt(parts[0]);
            int b = Integer.parseInt(parts[1]);
            for (int i = 2; i < 4; i++) {
                int v = Integer.parseInt(parts[i]);
                if (v < 0 || v > 255) return false;
            }
            // 100.64.0.0/10 → first octet 100, second octet 64..127.
            return a == 100 && b >= 64 && b <= 127;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // ==================== PLUMBING ====================

    private static String exec(String cmd) {
        Process p = null;
        try {
            p = new ProcessBuilder("sh", "-c", cmd).redirectErrorStream(false).start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append('\n');
            }
            if (!p.waitFor(EXEC_TIMEOUT_SEC, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                OverlinkConfig.log("status --json timed out");
                return null;
            }
            return sb.toString().trim();
        } catch (Exception e) {
            OverlinkConfig.log("status --json exec failed: " + e.getMessage());
            return null;
        } finally {
            if (p != null) p.destroy();
        }
    }

    private static String emptyToNull(String s) {
        return (s == null || s.isEmpty()) ? null : s;
    }
}
