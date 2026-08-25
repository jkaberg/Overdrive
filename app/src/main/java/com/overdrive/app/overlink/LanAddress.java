package com.overdrive.app.overlink;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Local-network address classification.
 *
 * <p>Two jobs, both of which the phone's parser also does independently:
 *
 * <ul>
 *   <li>Find the car's own private LAN address for the optional {@code lan_ip}
 *       hint and the §4.6 claim QR. A routable value is rejected — the phone
 *       refuses one, so emitting it would only produce a pairing that fails
 *       later rather than here.</li>
 *   <li>Decide whether an inbound request arrived over the tailnet, which is the
 *       authenticated channel §11.2 requires for registration and events. The
 *       LAN is not authenticated, and only the claim endpoint is served there.</li>
 * </ul>
 */
public final class LanAddress {

    private LanAddress() {}

    // ==================== OUR OWN ADDRESS ====================

    /**
     * The car's private IPv4 LAN address, or null when it only has routable or
     * Tailscale addresses. Tailscale's own CGNAT range is deliberately excluded:
     * {@code lan_ip} is a hint for reaching the car <em>before</em> the tunnel
     * exists, so a tailnet address there would be useless.
     */
    public static String privateAddress() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            if (ifaces == null) return null;
            String fallback = null;
            for (NetworkInterface ni : Collections.list(ifaces)) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                String name = ni.getName();
                // tailscale0 / tun* carry tailnet addresses, not LAN ones.
                if (name != null && (name.startsWith("tailscale") || name.startsWith("tun"))) continue;

                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (!(addr instanceof Inet4Address)) continue;
                    String ip = addr.getHostAddress();
                    if (ip == null || CarIdentity.isTailscaleAddress(ip)) continue;
                    if (!isPrivateOrLocal(ip)) continue;
                    // Prefer a real Wi-Fi/Ethernet address over link-local.
                    if (addr.isLinkLocalAddress()) {
                        if (fallback == null) fallback = ip;
                    } else {
                        return ip;
                    }
                }
            }
            return fallback;
        } catch (Exception e) {
            OverlinkConfig.log("LAN address lookup failed: " + e.getMessage());
            return null;
        }
    }

    // ==================== CLASSIFYING INBOUND REQUESTS ====================

    /**
     * True when the request came from a Tailscale peer — i.e. over the tunnel.
     * §11.2 requires registration and the event stream to refuse anything else.
     */
    public static boolean isTailnetPeer(SocketAddress clientAddress) {
        String ip = extractIp(clientAddress);
        return ip != null && CarIdentity.isTailscaleAddress(ip);
    }

    /** True for loopback, so the settings UI's own calls are recognised. */
    public static boolean isLoopback(SocketAddress clientAddress) {
        String ip = extractIp(clientAddress);
        if (ip == null) return false;
        return ip.equals("127.0.0.1") || ip.startsWith("127.") || ip.equals("::1")
                || ip.equals("0:0:0:0:0:0:0:1");
    }

    /**
     * True for a private, link-local or loopback source — the set the §4.6 claim
     * endpoint is willing to answer, since it must be reachable before the
     * tailnet is up.
     */
    public static boolean isLocalNetwork(SocketAddress clientAddress) {
        String ip = extractIp(clientAddress);
        return ip != null && isPrivateOrLocal(ip);
    }

    /**
     * RFC 1918, CGNAT-excluding, plus link-local, loopback and IPv6 ULA. Used
     * both for the address we advertise and for the sources we answer, so the
     * two can never drift apart.
     */
    public static boolean isPrivateOrLocal(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        if (ip.indexOf(':') >= 0) {
            String v6 = ip.toLowerCase(java.util.Locale.US);
            int pct = v6.indexOf('%');            // strip a zone id
            if (pct > 0) v6 = v6.substring(0, pct);
            return v6.equals("::1")
                    || v6.equals("0:0:0:0:0:0:0:1")
                    || v6.startsWith("fe80:")     // link-local
                    || v6.startsWith("fc") || v6.startsWith("fd"); // unique local
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        int a, b;
        try {
            a = Integer.parseInt(parts[0]);
            b = Integer.parseInt(parts[1]);
            for (int i = 2; i < 4; i++) {
                int v = Integer.parseInt(parts[i]);
                if (v < 0 || v > 255) return false;
            }
        } catch (NumberFormatException e) {
            return false;
        }
        if (a < 0 || a > 255 || b < 0 || b > 255) return false;
        if (a == 10) return true;                              // 10/8
        if (a == 172 && b >= 16 && b <= 31) return true;       // 172.16/12
        if (a == 192 && b == 168) return true;                 // 192.168/16
        if (a == 169 && b == 254) return true;                 // 169.254/16 link-local
        if (a == 127) return true;                             // loopback
        return false;
    }

    /**
     * Pull the bare IP out of a {@link SocketAddress}. Java renders these as
     * {@code /10.0.0.5:41234} or {@code host/10.0.0.5:41234}, and IPv6 as
     * {@code /fd7a:…:1234}, so the port is split from the right.
     */
    public static String extractIp(SocketAddress addr) {
        if (addr == null) return null;
        if (addr instanceof java.net.InetSocketAddress) {
            InetAddress ia = ((java.net.InetSocketAddress) addr).getAddress();
            if (ia != null) {
                String host = ia.getHostAddress();
                if (host == null) return null;
                int pct = host.indexOf('%');
                return pct > 0 ? host.substring(0, pct) : host;
            }
        }
        String s = addr.toString();
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(slash + 1);
        int colon = s.lastIndexOf(':');
        if (colon > 0) s = s.substring(0, colon);
        int pct = s.indexOf('%');
        if (pct > 0) s = s.substring(0, pct);
        return s.isEmpty() ? null : s;
    }
}
