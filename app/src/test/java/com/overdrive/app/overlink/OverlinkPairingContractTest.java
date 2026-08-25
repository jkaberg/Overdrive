package com.overdrive.app.overlink;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

/**
 * Guards the parts of the Overlink pairing contract the phone parses strictly.
 *
 * <p>The phone's {@code core/pairing.go} rejects a malformed payload rather than
 * guessing, so a car that drifts from these shapes fails loudly at pair time —
 * which is the intended behaviour, but it means a unilateral car-side change
 * surfaces to users as "pairing stopped working". These tests are the early
 * warning for that.
 *
 * <p>Scope note: everything here is pure logic. Anything that reads the unified
 * config or touches {@code android.util.Base64} needs an instrumented test —
 * this module has no Robolectric.
 */
public class OverlinkPairingContractTest {

    // ==================== §4.4 — ts_ip ====================

    @Test
    public void acceptsTailscaleAddressRanges() {
        // 100.64.0.0/10
        assertTrue(CarIdentity.isTailscaleAddress("100.64.0.1"));
        assertTrue(CarIdentity.isTailscaleAddress("100.101.102.103"));
        assertTrue(CarIdentity.isTailscaleAddress("100.127.255.255"));
        // fd7a:115c:a1e0::/48
        assertTrue(CarIdentity.isTailscaleAddress("fd7a:115c:a1e0::1"));
        assertTrue(CarIdentity.isTailscaleAddress("FD7A:115C:A1E0:AB12::1"));
    }

    @Test
    public void rejectsAddressesOutsideTailscaleRanges() {
        // Just outside 100.64/10 on either side — the classic off-by-one.
        assertFalse(CarIdentity.isTailscaleAddress("100.63.255.255"));
        assertFalse(CarIdentity.isTailscaleAddress("100.128.0.1"));
        // Ordinary LAN and routable addresses.
        assertFalse(CarIdentity.isTailscaleAddress("192.168.1.42"));
        assertFalse(CarIdentity.isTailscaleAddress("10.0.0.5"));
        assertFalse(CarIdentity.isTailscaleAddress("8.8.8.8"));
        // A different ULA prefix is not Tailscale's.
        assertFalse(CarIdentity.isTailscaleAddress("fd00::1"));
        // Malformed.
        assertFalse(CarIdentity.isTailscaleAddress(""));
        assertFalse(CarIdentity.isTailscaleAddress(null));
        assertFalse(CarIdentity.isTailscaleAddress("100.64.0"));
        assertFalse(CarIdentity.isTailscaleAddress("100.64.0.999"));
    }

    // ==================== §4.4 / §4.6 — lan_ip and addr ====================

    @Test
    public void acceptsPrivateLinkLocalAndLoopbackAddresses() {
        assertTrue(LanAddress.isPrivateOrLocal("10.0.0.5"));
        assertTrue(LanAddress.isPrivateOrLocal("172.16.0.1"));
        assertTrue(LanAddress.isPrivateOrLocal("172.31.255.254"));
        assertTrue(LanAddress.isPrivateOrLocal("192.168.1.42"));
        assertTrue(LanAddress.isPrivateOrLocal("169.254.1.1"));
        assertTrue(LanAddress.isPrivateOrLocal("127.0.0.1"));
        assertTrue(LanAddress.isPrivateOrLocal("::1"));
        assertTrue(LanAddress.isPrivateOrLocal("fe80::1%wlan0"));
        assertTrue(LanAddress.isPrivateOrLocal("fd00::1"));
    }

    @Test
    public void rejectsRoutableAddresses() {
        // A routable value in lan_ip is rejected by the phone, so emitting one
        // would only produce a pairing that fails later rather than here.
        assertFalse(LanAddress.isPrivateOrLocal("8.8.8.8"));
        assertFalse(LanAddress.isPrivateOrLocal("1.1.1.1"));
        assertFalse(LanAddress.isPrivateOrLocal("2606:4700::1111"));
        // 172.15 and 172.32 bracket the /12 — both are public.
        assertFalse(LanAddress.isPrivateOrLocal("172.15.0.1"));
        assertFalse(LanAddress.isPrivateOrLocal("172.32.0.1"));
        assertFalse(LanAddress.isPrivateOrLocal(""));
        assertFalse(LanAddress.isPrivateOrLocal(null));
    }

    @Test
    public void extractsIpFromSocketAddressRenderings() {
        assertEquals("10.0.0.5", LanAddress.extractIp(
                new java.net.InetSocketAddress("10.0.0.5", 41234)));
        assertEquals("127.0.0.1", LanAddress.extractIp(
                new java.net.InetSocketAddress("127.0.0.1", 8080)));
        assertEquals(null, LanAddress.extractIp(null));
    }

    // ==================== §4.4 — tag ====================

    @Test
    public void tagMatchesThePhonesRegex() {
        assertTrue(OverlinkConfig.isValidTag("tag:overdrive-phone"));
        assertTrue(OverlinkConfig.isValidTag("tag:overdrive-car"));
        assertTrue(OverlinkConfig.isValidTag("tag:a"));
        assertTrue(OverlinkConfig.isValidTag("tag:0abc-def"));

        assertFalse("no prefix", OverlinkConfig.isValidTag("overdrive-phone"));
        assertFalse("uppercase", OverlinkConfig.isValidTag("tag:Overdrive-Phone"));
        assertFalse("leading hyphen", OverlinkConfig.isValidTag("tag:-phone"));
        assertFalse("underscore", OverlinkConfig.isValidTag("tag:over_drive"));
        assertFalse("empty label", OverlinkConfig.isValidTag("tag:"));
        assertFalse(OverlinkConfig.isValidTag(null));
    }

    // ==================== §4.4 — the QR URI ====================

    @Test
    public void buildsThePlainUriFormWithEveryRequiredField() {
        String uri = OverlinkPairingManager.buildUri(samplePayload());

        assertTrue(uri.startsWith("overdrive://pair?"));
        // `v` first, so a version mismatch is the first thing a parser sees.
        assertTrue(uri.startsWith("overdrive://pair?v=1&"));

        for (String required : new String[] {
                "nonce=", "ak=", "tag=", "node_id=", "ts_ip=", "fqdn=", "port=" }) {
            assertTrue("missing required field " + required, uri.contains("&" + required));
        }
        // Tag is percent-encoded, since ':' is not query-safe.
        assertTrue(uri.contains("tag=tag%3Aoverdrive-phone"));
        // caps is a comma-joined list, not a JSON array.
        assertTrue(uri.contains("caps=registry%2Cevents"));
        // The port comes from the running server, not a hardcoded 8080.
        assertTrue(uri.contains("port=9090"));
    }

    @Test
    public void omitsAbsentOptionalFields() {
        JSONObject payload = samplePayload();
        payload.remove("dt");
        payload.remove("lan_ip");

        String uri = OverlinkPairingManager.buildUri(payload);
        assertFalse(uri.contains("dt="));
        assertFalse(uri.contains("lan_ip="));
    }

    @Test
    public void plainUriStaysInsideTheLegibilityBudget() {
        // Pairing has to work on a real head unit, in sunlight, at arm's length,
        // so a realistic payload must not spill into the compact base64 form.
        String uri = OverlinkPairingManager.buildUri(samplePayload());
        assertTrue("URI grew to " + uri.length() + " bytes",
                uri.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 800);
    }

    /** A realistic payload: everything the car sends, with plausible lengths. */
    private static JSONObject samplePayload() {
        JSONObject p = new JSONObject();
        try {
            p.put("v", 1);
            p.put("nonce", "AbCdEfGhIjKlMnOpQrStUw");
            p.put("ak", "tskey-auth-kBvQr7CNTRL-5tGhJk8mNpQrStUvWxYz1234");
            p.put("tag", "tag:overdrive-phone");
            p.put("node_id", "nPGnBW3CNTRL");
            p.put("ts_ip", "100.101.102.103");
            p.put("fqdn", "overdrive.tail1234.ts.net");
            p.put("port", 9090);
            p.put("caps", new JSONArray().put("registry").put("events").put("auth_token"));
            p.put("car_name", "Seal");
            p.put("car_model", "seal");
            p.put("lan_ip", "192.168.1.42");
            p.put("dt", "byd-a1b2c3d4-x7k9m2p5q3r6s8t1");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        return p;
    }

    // ==================== §11.6 — failure classification ====================

    @Test
    public void classifiesTheTagOwnershipFailureDistinctly() {
        // The common first-run failure. A generic "mint failed" makes it close
        // to undiagnosable, so it has to be separable from every other 4xx.
        assertTrue(apiError(400, "requested tags [tag:overdrive-phone] are invalid or not permitted")
                .isTagOwnershipError());
        assertTrue(apiError(403, "calling user does not have access to the tagOwners entry")
                .isTagOwnershipError());

        assertFalse(apiError(500, "internal server error").isTagOwnershipError());
        assertFalse(apiError(0, null).isTagOwnershipError());
    }

    @Test
    public void separatesCredentialAndOfflineFailures() {
        assertTrue(apiError(401, "invalid_client").isCredentialError());
        assertTrue(apiError(403, "forbidden").isCredentialError());
        assertFalse(apiError(500, "boom").isCredentialError());

        // status 0 is the transport failure — the car has no internet, which is
        // a different message and a different action from a rejected credential.
        assertTrue(apiError(0, null).isOffline());
        assertFalse(apiError(401, "invalid_client").isOffline());
    }

    private static TailscaleApiClient.ApiException apiError(int status, String apiMessage) {
        return new TailscaleApiClient.ApiException(status, apiMessage, "test");
    }
}
