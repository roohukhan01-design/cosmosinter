# AirLink 3.0 — Phase 1 implementation notes

## Architecture

- `index.html` is now a small application shell. Styles and JavaScript are loaded from `css/` and `js/`.
- `js/core/` contains persistent browser storage and application-state initialization.
- `js/views/` owns the primary HTML view rendering.
- `js/api/native.js` is the Capacitor bridge. Outside the installed Android app it reports that native sharing is unavailable instead of simulating transfers.
- `js/i18n/` starts the English/Urdu string table; `js/theme.js` applies light/dark/auto system preference.
- `AirLinkSecurity.java` contains pairing, rate-limit, filename/upload validation and per-session TLS identity primitives.
- `LanServer` serves both the existing HTTP compatibility endpoint and a second TLS endpoint. Both use the existing request/transfer handlers.
- `LanClient` can pin the exact SHA-256 certificate fingerprint before sending credentials. The native `LanClient` sends device secrets only on pinned TLS connections. The browser client retains a device secret over its explicitly unencrypted HTTP fallback, which is why its warning remains visible.

## Security behaviour

- Pairing codes expire after five minutes and are atomically consumed by the first successful new-device pairing.
- A trusted device receives a 256-bit random device secret and a separate 128-bit session token. Device secrets are stored in Android private SharedPreferences and restored when a new sharing session starts.
- Revoking a trusted device deletes its active session and device secret.
- Failed authentication attempts are limited globally (30/minute) and per IP (five failures before exponential backoff, capped at 30 minutes).
- Uploads reject path components, enforce a 20 GiB maximum, use overflow-safe offset validation and retain the existing low-storage check.
- A fresh P-256 self-signed certificate is created for each sharing session. Its SHA-256 fingerprint is sent in the QR/link and the UDP discovery beacon. Native peer connections pin the exact certificate before authentication.
- The fingerprint is displayed on both sides of the phone-to-phone pairing flow. Compare it on the two phones before entering the pairing code; this is important because UDP discovery itself is not authenticated.
- `pc.html` remains on HTTP for browser compatibility and displays a persistent **Not encrypted** warning. Browser traffic, including browser-side device-secret reauthentication, is not protected by TLS.

## Verification

Run the pure-Java engine suite:

```sh
javac -d /tmp/airlink-test AirLinkSecurity.java LanServer.java LanClient.java Beacon.java AirTest.java
java -cp /tmp/airlink-test com.roohu.airlink.AirTest
```

The workflow also syntax-checks every ES module and the `pc.html` script. The full Android Gradle/APK build must still run in GitHub Actions or an Android SDK-equipped environment.
