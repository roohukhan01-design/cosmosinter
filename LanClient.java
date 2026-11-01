package com.roohu.airlink;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.util.HashMap;
import java.util.Map;

/**
 * LAN client used to talk to another AirLink phone (protocol 2).
 * Supports ordinary HTTP compatibility and exact-fingerprint-pinned TLS.
 * Downloads and uploads can resume after a Wi-Fi drop and are verified with SHA-256.
 */
public class LanClient {
    private static final Map<String, String> TLS_PINS = new ConcurrentHashMap<String, String>();
    private static final Map<String, String> DEVICE_SECRETS = new ConcurrentHashMap<String, String>();
    public static void pinTls(String host, int port, String fingerprint) {
        if (host == null || fingerprint == null || !fingerprint.matches("(?i)[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid TLS fingerprint");
        TLS_PINS.put(host + ":" + port, fingerprint.toUpperCase(java.util.Locale.ROOT));
    }
    public static void clearTlsPin(String host, int port) { TLS_PINS.remove(host + ":" + port); }
    private static String secretKey(String host, int port, String clientId) { return host + ":" + clientId; }
    public static String deviceSecretFor(String host, int port, String clientId) { return DEVICE_SECRETS.get(secretKey(host, port, clientId)); }
    public static void setDeviceSecret(String host, int port, String clientId, String secret) { if (clientId != null && secret != null) DEVICE_SECRETS.put(secretKey(host, port, clientId), secret); }

    public static final int CHUNK = 4 * 1024 * 1024;

    public interface Progress {
        void on(long done, long total);
    }

    public interface Cancel {
        boolean is();
    }

    /** Opens the file from the start every time it is called. */
    public interface Source {
        InputStream open() throws IOException;
    }

    /** The other side answered with an error that retrying will not fix (or a retryable one, see code). */
    public static class HttpError extends IOException {
        public final int status;
        public final String code;
        public final long received;

        HttpError(int status, String msg, String code, long received) {
            super(msg);
            this.status = status;
            this.code = code == null ? "" : code;
            this.received = received;
        }

        public boolean isAuth() {
            return status == 401;
        }
    }

    public static class CancelledException extends IOException {
        public CancelledException() {
            super("Cancelled");
        }
    }

    public static class DownloadState {
        public long done = 0;
        public long total = -1;
        public final MessageDigest md = LanServer.sha256();
    }

    private static class Head {
        int status;
        Map<String, String> h = new HashMap<String, String>();

        long length() {
            String v = h.get("content-length");
            if (v == null) return -1;
            try {
                return Long.parseLong(v.trim());
            } catch (Exception e) {
                return -1;
            }
        }
    }

    private static Socket open(String host, int port, int readMs) throws IOException {
        final String pin = TLS_PINS.get(host + ":" + port);
        Socket s;
        if (pin != null) {
            try {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { throw new CertificateException("Client certificates not used"); }
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        if (chain == null || chain.length == 0) throw new CertificateException("Missing server certificate");
                        try {
                            chain[0].checkValidity();
                            String actual = LanServer.hex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));
                            if (!pin.equalsIgnoreCase(actual)) throw new CertificateException("AirLink certificate fingerprint mismatch");
                        } catch (CertificateException e) { throw e; }
                        catch (Exception e) { throw new CertificateException("Could not verify AirLink certificate", e); }
                    }
                }}, new SecureRandom());
                SSLSocket ssl = (SSLSocket)ctx.getSocketFactory().createSocket();
                ssl.connect(new InetSocketAddress(host, port), 6000); ssl.setSoTimeout(readMs); ssl.startHandshake(); s = ssl;
            } catch (Exception e) { throw new IOException("Secure AirLink connection failed: " + e.getMessage(), e); }
        } else {
            s = new Socket(); s.connect(new InetSocketAddress(host, port), 6000);
        }
        s.setSoTimeout(readMs); s.setTcpNoDelay(true);
        try { s.setSendBufferSize(262144); s.setReceiveBufferSize(262144); } catch (Exception e) { }
        return s;
    }

    private static String line(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c, n = 0;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                int l = sb.length();
                if (l > 0 && sb.charAt(l - 1) == '\r') sb.setLength(l - 1);
                return sb.toString();
            }
            sb.append((char) c);
            if (++n > 16384) throw new IOException("Bad answer");
        }
        return n == 0 ? null : sb.toString();
    }

    private static Head readHead(InputStream in) throws IOException {
        String sl = line(in);
        if (sl == null) throw new IOException("The other phone did not answer");
        String[] p = sl.split(" ", 3);
        if (p.length < 2) throw new IOException("Bad answer");
        Head h = new Head();
        try {
            h.status = Integer.parseInt(p[1].trim());
        } catch (Exception e) {
            throw new IOException("Bad answer");
        }
        String l;
        while ((l = line(in)) != null && !l.isEmpty()) {
            int c = l.indexOf(':');
            if (c > 0) h.h.put(l.substring(0, c).trim().toLowerCase(), l.substring(c + 1).trim());
        }
        return h;
    }

    private static String readBody(InputStream in, Head h) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        long n = h.length();
        byte[] buf = new byte[8192];
        long done = 0;
        while (n < 0 || done < n) {
            int want = n < 0 ? buf.length : (int) Math.min(buf.length, n - done);
            int r = in.read(buf, 0, want);
            if (r < 0) break;
            bo.write(buf, 0, r);
            done += r;
            if (done > 4000000) break;
        }
        return new String(bo.toByteArray(), StandardCharsets.UTF_8);
    }

    /** Tiny JSON string reader: finds "key":"value". Good enough for our own server. */
    public static String jstr(String body, String key) {
        String pat = "\"" + key + "\":\"";
        int i = body.indexOf(pat);
        if (i < 0) return null;
        StringBuilder b = new StringBuilder();
        for (int k = i + pat.length(); k < body.length(); k++) {
            char c = body.charAt(k);
            if (c == '\\' && k + 1 < body.length()) {
                char d = body.charAt(++k);
                b.append(d == 'n' ? '\n' : d == 't' ? '\t' : d == 'r' ? '\r' : d);
            } else if (c == '"') {
                return b.toString();
            } else {
                b.append(c);
            }
        }
        return null;
    }

    public static long jnum(String body, String key, long def) {
        String pat = "\"" + key + "\":";
        int i = body.indexOf(pat);
        if (i < 0) return def;
        int s = i + pat.length(), e = s;
        while (e < body.length() && (Character.isDigit(body.charAt(e)) || body.charAt(e) == '-')) e++;
        try {
            return Long.parseLong(body.substring(s, e));
        } catch (Exception x) {
            return def;
        }
    }

    private static HttpError errorOf(String body, int status) {
        String msg = jstr(body, "error");
        String code = jstr(body, "code");
        if (msg == null) {
            msg = status == 401 ? "Session expired" : status == 403 ? "Wrong code" : status == 429 ? "Too many wrong codes. Wait one minute."
                    : status == 404 ? "File not found" : status == 503 ? "The other phone is busy" : "Error " + status;
        }
        return new HttpError(status, msg, code, jnum(body, "received", -1));
    }

    private static void request(OutputStream out, String method, String host, int port, String path, String token, String extra) throws IOException {
        String r = method + " " + path + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n"
                + (token == null ? "" : "X-Token: " + token + "\r\n") + extra + "Connection: close\r\n\r\n";
        out.write(r.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static String enc(String s) throws IOException {
        return URLEncoder.encode(s, "UTF-8").replace("+", "%20");
    }

    /** Trade the 6 digit code for a session token. May wait while the other phone's owner decides. */
    public static String auth(String host, int port, String key, String clientId, String clientName) throws IOException {
        Socket s = open(host, port, 60000);
        try {
            OutputStream out = s.getOutputStream();
            String extra = "X-Key: " + key + "\r\nX-Client-Id: " + clientId + "\r\nX-Client-Name: " + enc(clientName) + "\r\n";
            String secret = TLS_PINS.containsKey(host + ":" + port) ? DEVICE_SECRETS.get(secretKey(host, port, clientId)) : null;
            if (secret != null) extra += "X-Device-Secret: " + secret + "\r\n";
            request(out, "POST", host, port, "/api/auth", null, extra + "Content-Length: 0\r\n");
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream(), 8192);
            Head h = readHead(in); String b = readBody(in, h);
            if (h.status != 200) throw errorOf(b, h.status);
            String t = jstr(b, "token"); String ds = jstr(b, "deviceSecret");
            if (ds != null && ds.matches("[0-9a-f]{64}")) DEVICE_SECRETS.put(secretKey(host, port, clientId), ds);
            if (t == null) throw new IOException("Bad answer");
            return t;
        } finally { try { s.close(); } catch (IOException e) { } }
    }

    public static String getText(String host, int port, String token, String path) throws IOException {
        return getText(host, port, token, path, 20000);
    }

    /** GET a small text answer (JSON). */
    public static String getText(String host, int port, String token, String path, int readMs) throws IOException {
        Socket s = open(host, port, readMs);
        try {
            OutputStream out = s.getOutputStream();
            request(out, "GET", host, port, path, token, "");
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream(), 65536);
            Head h = readHead(in);
            String b = readBody(in, h);
            if (h.status != 200) throw errorOf(b, h.status);
            return b;
        } finally {
            try { s.close(); } catch (IOException e) { }
        }
    }

    public static String postText(String host, int port, String token, String path, String text, String extra) throws IOException {
        Socket s = open(host, port, 20000);
        try {
            byte[] body = text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8);
            OutputStream out = s.getOutputStream();
            request(out, "POST", host, port, path, token, extra + "Content-Length: " + body.length + "\r\n");
            out.write(body);
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream(), 8192);
            Head h = readHead(in);
            String b = readBody(in, h);
            if (h.status != 200) throw errorOf(b, h.status);
            return b;
        } finally {
            try { s.close(); } catch (IOException e) { }
        }
    }

    /**
     * Download one shared file, appending to os from st.done. Call again after a drop and it resumes
     * (the server must support Range). st.md always holds the hash of the bytes written so far.
     */
    public static void download(String host, int port, String token, String id, OutputStream os, DownloadState st, Progress p, Cancel c) throws IOException {
        Socket s = open(host, port, 30000);
        try {
            OutputStream out = s.getOutputStream();
            request(out, "GET", host, port, "/f/" + enc(id), token, st.done > 0 ? "Range: bytes=" + st.done + "-\r\n" : "");
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream(), 65536);
            Head h = readHead(in);
            if (h.status == 416 && st.total >= 0 && st.done >= st.total) return;
            if (h.status != 200 && h.status != 206) throw errorOf(readBody(in, h), h.status);
            if (st.done > 0 && h.status != 206) throw new HttpError(h.status, "The other phone cannot resume this file", "noresume", -1);
            long part = h.length();
            if (part >= 0) st.total = st.done + part;
            byte[] buf = new byte[65536];
            long last = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                if (c != null && c.is()) throw new CancelledException();
                os.write(buf, 0, n);
                st.md.update(buf, 0, n);
                st.done += n;
                long now = System.currentTimeMillis();
                if (p != null && now - last > 400) {
                    last = now;
                    p.on(st.done, st.total);
                }
            }
            if (st.total >= 0 && st.done != st.total) throw new IOException("The connection stopped before the file was complete");
            if (st.total < 0) st.total = st.done;
            if (p != null) p.on(st.done, st.total);
        } finally {
            try { s.close(); } catch (IOException e) { }
        }
    }

    /** Ask the other phone for the SHA-256 of one of its shared files. */
    public static String remoteHash(String host, int port, String token, String id) throws IOException {
        String b = getText(host, port, token, "/api/hash/" + enc(id), 600000);
        String h = jstr(b, "sha256");
        if (h == null) throw new IOException("Bad answer");
        return h;
    }

    private static long receivedOn(String host, int port, String token, String id) {
        try {
            String b = getText(host, port, token, "/api/upload-status?id=" + enc(id), 8000);
            return jnum(b, "received", -1);
        } catch (HttpError e) {
            return -1;
        } catch (IOException e) {
            return -2;
        }
    }

    private static void sendChunk(String host, int port, String token, String name, String uid, long offset, long len, long total,
                                  InputStream src, MessageDigest md, long[] consumed, Progress p, Cancel c) throws IOException {
        Socket s = open(host, port, 60000);
        try {
            OutputStream out = s.getOutputStream();
            request(out, "POST", host, port, "/upload", token, "X-Filename: " + enc(name) + "\r\nX-Upload-Id: " + uid + "\r\nX-Offset: " + offset
                    + "\r\nX-Total: " + total + "\r\nContent-Length: " + len + "\r\n");
            byte[] buf = new byte[65536];
            long sent = 0, last = 0;
            while (sent < len) {
                if (c != null && c.is()) throw new CancelledException();
                int n = src.read(buf, 0, (int) Math.min(buf.length, len - sent));
                if (n < 0) throw new IOException("The file ended too early");
                out.write(buf, 0, n);
                md.update(buf, 0, n);
                sent += n;
                consumed[0] += n;
                long now = System.currentTimeMillis();
                if (p != null && now - last > 400) {
                    last = now;
                    p.on(consumed[0], total);
                }
            }
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream(), 8192);
            Head h = readHead(in);
            String b = readBody(in, h);
            if (h.status != 200) throw errorOf(b, h.status);
        } finally {
            try { s.close(); } catch (IOException e) { }
        }
    }

    /**
     * Send one file in 4 MB pieces. After a drop it asks the other side how much arrived and carries on.
     * Returns the SHA-256 the other side confirmed.
     */
    public static String upload(String host, int port, String token, String name, Source src, long len, String uid, Progress p, Cancel c) throws IOException {
        MessageDigest md = LanServer.sha256();
        long[] consumed = {0};
        long acked = 0;
        InputStream in = src.open();
        int fails = 0;
        try {
            boolean sentEmpty = false;
            while (acked < len || (len == 0 && !sentEmpty)) {
                if (c != null && c.is()) throw new CancelledException();
                long chunk = Math.min(CHUNK, len - acked);
                try {
                    sendChunk(host, port, token, name, uid, acked, chunk, len, in, md, consumed, p, c);
                    acked += chunk;
                    sentEmpty = true;
                    fails = 0;
                } catch (CancelledException e) {
                    throw e;
                } catch (HttpError e) {
                    if (e.status == 401 || e.status == 410 || e.status == 507 || e.status == 400 || e.status == 422 || e.status == 403) throw e;
                    if (e.code.equals("restart")) throw e;
                    if (++fails > 6) throw e;
                    if (e.code.equals("offset") && e.received >= 0) {
                        acked = e.received;
                    } else {
                        sleep(800L * fails);
                        long r = receivedOn(host, port, token, uid);
                        if (r >= 0) acked = r;
                    }
                    in = reposition(in, src, md, consumed, acked);
                } catch (IOException e) {
                    if (++fails > 6) throw e;
                    sleep(800L * fails);
                    long r = receivedOn(host, port, token, uid);
                    if (r == -2) {
                        sleep(1500L);
                        r = receivedOn(host, port, token, uid);
                    }
                    if (r == -1 && acked > 0) throw new IOException("The other phone lost the partial file");
                    if (r >= 0) acked = r;
                    in = reposition(in, src, md, consumed, acked);
                }
            }
        } finally {
            try { in.close(); } catch (IOException e) { }
        }
        String sha = LanServer.hex(md.digest());
        Socket s = open(host, port, 120000);
        try {
            OutputStream out = s.getOutputStream();
            request(out, "POST", host, port, "/api/upload-finish", token, "X-Upload-Id: " + uid + "\r\nX-Sha256: " + sha + "\r\nContent-Length: 0\r\n");
            out.flush();
            InputStream rin = new BufferedInputStream(s.getInputStream(), 8192);
            Head h = readHead(rin);
            String b = readBody(rin, h);
            if (h.status != 200) throw errorOf(b, h.status);
            if (p != null) p.on(len, len);
            return sha;
        } finally {
            try { s.close(); } catch (IOException e) { }
        }
    }

    /** Reopen the file and rebuild the hash so both match the position the other side confirmed. */
    private static InputStream reposition(InputStream cur, Source src, MessageDigest md, long[] consumed, long to) throws IOException {
        if (consumed[0] == to) return cur;
        try { cur.close(); } catch (IOException e) { }
        InputStream in = src.open();
        md.reset();
        byte[] buf = new byte[65536];
        long left = to;
        while (left > 0) {
            int n = in.read(buf, 0, (int) Math.min(buf.length, left));
            if (n < 0) throw new IOException("The file ended too early");
            md.update(buf, 0, n);
            left -= n;
        }
        consumed[0] = to;
        return in;
    }

    private static void sleep(long ms) throws IOException {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            throw new IOException("Interrupted");
        }
    }
}
