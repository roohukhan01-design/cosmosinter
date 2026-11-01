package com.roohu.airlink;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocket;
import java.net.Socket;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * AirLink LAN server (protocol 2): HTTP compatibility plus per-session pinned TLS. Pure Java so it can be tested on a computer.
 *
 * Highlights
 *  - the 6 digit code is only used once, to get a random session token
 *  - optional approval of every new device (asked on the phone)
 *  - resumable chunked uploads with SHA-256 verification
 *  - Range downloads, SHA-256 endpoint, "download everything as ZIP"
 *  - shared text clipboard, idle auto-off, bounded thread pool
 */
public class LanServer {

    public static final int PROTO = 2;
    private static final int MAX_SESSIONS = 12;
    private static final int MAX_CLIPS = 30;
    private static final int MAX_CLIP_BYTES = 65536;

    public static class Item {
        public String id;
        public String name;
        public long size;
        public Object ref;
    }

    public interface Upload {
        OutputStream stream();

        /** Close the file. ok=false means delete the half file. Returns a short place name. */
        String finish(boolean ok) throws IOException;
    }

    public static class Clip {
        public String id;
        public String from;
        public String text;
        public long ts;
    }

    public static class Session {
        public String id;
        public String token;
        public String clientId;
        public String name;
        public String ip;
        public long created;
        public volatile long lastSeen;
    }

    public interface Host {
        List<Item> shared();

        InputStream open(Item item) throws IOException;

        Upload createUpload(String name, long length) throws IOException;

        InputStream page() throws IOException;

        String deviceName();

        /** Free bytes for received files, or -1 when unknown. */
        long freeSpace();

        void onProgress(String name, long done, long total, boolean upload);

        void onReceived(String name, long size, String where, String sha256);

        /** Called on a worker thread. Block until the person on the phone decides (max ~45 s). */
        boolean approve(String clientName, String ip, String clientId);

        void onSessions();

        void onClip(Clip clip);

        void onIdleStop();
    }

    private static class UpState {
        String id, name;
        Upload up;
        OutputStream os;
        long received, total;
        MessageDigest md;
        volatile long touched;
        boolean finished, legacy;
        String where = "", sha = "";
        Socket sock;
    }

    private final Host host;
    private ServerSocket ss;
    private SSLServerSocket tlsSs;
    private volatile int tlsPort;
    private volatile String tlsFingerprint = "";
    private volatile boolean running;
    private boolean askApproval;
    private long idleMs;
    private ThreadPoolExecutor pool;
    private Thread watcher;
    private final SecureRandom rnd = new SecureRandom();
    private final Set<Socket> open = Collections.newSetFromMap(new ConcurrentHashMap<Socket, Boolean>());
    private final AirLinkSecurity.AttemptLimiter limiter = new AirLinkSecurity.AttemptLimiter();
    private final AirLinkSecurity.PairingCode pairing = new AirLinkSecurity.PairingCode();
    private final Map<String, String> deviceSecrets = new ConcurrentHashMap<String, String>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<String, Session>();
    private final Map<String, Session> trustedDevices = new ConcurrentHashMap<String, Session>();
    private final Set<String> trusted = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
    private final ConcurrentHashMap<String, Object> approvalLocks = new ConcurrentHashMap<String, Object>();
    private final ConcurrentHashMap<String, UpState> ups = new ConcurrentHashMap<String, UpState>();
    private final Set<String> cancelledUploads = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
    private final Map<String, Long> cancelNames = new ConcurrentHashMap<String, Long>();
    private final Map<String, String> hashCache = new ConcurrentHashMap<String, String>();
    private final LinkedList<Clip> clips = new LinkedList<Clip>();
    private int clipSeq = 0;
    private final AtomicInteger active = new AtomicInteger();
    private volatile long lastActivity = System.currentTimeMillis();

    public LanServer(Host host) { this(host, Collections.<String, String>emptyMap()); }

    public LanServer(Host host, Map<String, String> restoredSecrets) {
        this.host = host;
        if (restoredSecrets != null) for (Map.Entry<String, String> entry : restoredSecrets.entrySet()) {
            String cid = entry.getKey(), secret = entry.getValue();
            if (cid == null || !cid.matches("[A-Za-z0-9_\\-]{6,64}") || secret == null || !secret.matches("[0-9a-f]{64}")) continue;
            deviceSecrets.put(cid, secret); trusted.add(cid);
            Session saved = new Session(); saved.id = randomHex(4); saved.clientId = cid;
            saved.name = "Previously trusted device"; saved.ip = "Previously paired";
            saved.created = saved.lastSeen = System.currentTimeMillis();
            trustedDevices.put(cid, saved);
        }
    }

    public Map<String, String> exportTrustedSecrets() {
        return new HashMap<String, String>(deviceSecrets);
    }

    public int start(int port, String accessKey) throws IOException {
        return start(port, accessKey, false, 0);
    }

    public synchronized int start(int port, String accessKey, boolean approval, int idleMinutes) throws IOException {
        stop();
        ServerSocket s = new ServerSocket();
        s.setReuseAddress(true);
        s.bind(new InetSocketAddress(port));
        AirLinkSecurity.TlsEndpoint tls;
        try { tls = AirLinkSecurity.createTlsEndpoint(0); }
        catch (Exception e) { try { s.close(); } catch (IOException ignored) { } throw new IOException("Could not create session TLS identity", e); }
        ss = s;
        tlsSs = tls.socket;
        tlsPort = tls.socket.getLocalPort();
        tlsFingerprint = tls.fingerprint;
        pairing.issue(accessKey, System.currentTimeMillis(), AirLinkSecurity.DEFAULT_PAIRING_TTL_MS);
        askApproval = approval;
        idleMs = idleMinutes > 0 ? idleMinutes * 60000L : 0;
        lastActivity = System.currentTimeMillis();
        pool = new ThreadPoolExecutor(2, 32, 30, TimeUnit.SECONDS, new SynchronousQueue<Runnable>());
        running = true;
        final ServerSocket srv = s;
        final ThreadPoolExecutor ex = pool;
        Thread t = new Thread(new Runnable() {
            public void run() {
                while (running) {
                    try {
                        final Socket c = srv.accept();
                        open.add(c);
                        try {
                            ex.execute(new Runnable() {
                                public void run() {
                                    try {
                                        handle(c);
                                    } catch (Throwable e) {
                                        // client left or bad request
                                    } finally {
                                        open.remove(c);
                                        try { c.close(); } catch (IOException e) { }
                                    }
                                }
                            });
                        } catch (RejectedExecutionException busy) {
                            open.remove(c);
                            try {
                                byte[] b = "{\"ok\":false,\"error\":\"The phone is busy. Try again.\",\"code\":\"busy\"}".getBytes(StandardCharsets.UTF_8);
                                send(new BufferedOutputStream(c.getOutputStream()), 503, "application/json; charset=utf-8", b);
                            } catch (IOException e) { }
                            try { c.close(); } catch (IOException e) { }
                        }
                    } catch (IOException e) {
                        if (!running) break;
                    }
                }
            }
        }, "airlink-accept");
        t.setDaemon(true);
        t.start();
        final SSLServerSocket secureSrv = tlsSs;
        Thread secureAccept = new Thread(new Runnable() {
            public void run() {
                while (running && !secureSrv.isClosed()) {
                    try {
                        final Socket c = secureSrv.accept();
                        open.add(c);
                        try {
                            ex.execute(new Runnable() {
                                public void run() {
                                    try { handle(c); }
                                    catch (Throwable e) { /* disconnected or invalid request */ }
                                    finally { open.remove(c); try { c.close(); } catch (IOException ignored) { } }
                                }
                            });
                        } catch (RejectedExecutionException busy) {
                            open.remove(c); try { c.close(); } catch (IOException ignored) { }
                        }
                    } catch (IOException e) { if (!running) break; }
                }
            }
        }, "airlink-tls-accept");
        secureAccept.setDaemon(true);
        secureAccept.start();
        watcher = new Thread(new Runnable() {
            public void run() {
                boolean idleFired = false;
                while (running) {
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        break;
                    }
                    housekeeping();
                    if (idleMs > 0 && !idleFired && active.get() == 0 && System.currentTimeMillis() - lastActivity > idleMs) {
                        idleFired = true;
                        try { host.onIdleStop(); } catch (Throwable e) { }
                    }
                }
            }
        }, "airlink-watch");
        watcher.setDaemon(true);
        watcher.start();
        return s.getLocalPort();
    }

    public synchronized void stop() {
        running = false;
        if (watcher != null) {
            watcher.interrupt();
            watcher = null;
        }
        if (ss != null) { try { ss.close(); } catch (IOException e) { } ss = null; }
        if (tlsSs != null) { try { tlsSs.close(); } catch (IOException e) { } tlsSs = null; }
        tlsPort = 0; tlsFingerprint = "";
        for (Socket c : open) {
            try { c.close(); } catch (IOException e) { }
        }
        open.clear();
        for (UpState st : new ArrayList<UpState>(ups.values())) {
            synchronized (st) {
                if (!st.finished) {
                    try { st.up.finish(false); } catch (Exception e) { }
                    st.finished = true;
                }
            }
        }
        ups.clear();
        cancelledUploads.clear();
        sessions.clear();
        pairing.clear();
        approvalLocks.clear();
        hashCache.clear();
        if (pool != null) {
            pool.shutdownNow();
            pool = null;
        }
    }

    public int tlsPort() { return tlsPort; }
    public String tlsFingerprint() { return tlsFingerprint; }
    public long pairingExpiresAt() { return pairing.expiresAt(); }

    public boolean isRunning() {
        return running;
    }

    public int activeTransfers() {
        return active.get();
    }

    /* ---------------- sessions, clipboard, control ---------------- */

    public List<Session> sessions() {
        List<Session> l = new ArrayList<Session>(sessions.values());
        Collections.sort(l, new java.util.Comparator<Session>() {
            public int compare(Session a, Session b) {
                return a.created < b.created ? -1 : a.created > b.created ? 1 : 0;
            }
        });
        return l;
    }

    public List<Session> trustedDevices() {
        List<Session> l = new ArrayList<Session>(trustedDevices.values());
        Collections.sort(l, new java.util.Comparator<Session>() {
            public int compare(Session a, Session b) { return a.created < b.created ? -1 : a.created > b.created ? 1 : 0; }
        });
        return l;
    }

    public void revoke(String sid) {
        for (Session s : new ArrayList<Session>(trustedDevices.values())) {
            if (s.id.equals(sid)) {
                trustedDevices.remove(s.clientId);
                trusted.remove(s.clientId);
                deviceSecrets.remove(s.clientId);
                for (Session activeSession : new ArrayList<Session>(sessions.values()))
                    if (activeSession.clientId.equals(s.clientId)) sessions.remove(activeSession.token);
            }
        }
        host.onSessions();
    }

    /** New code: every device has to connect again. */
    public void setKey(String newKey) {
        sessions.clear();
        pairing.issue(newKey, System.currentTimeMillis(), AirLinkSecurity.DEFAULT_PAIRING_TTL_MS);
        host.onSessions();
    }

    public synchronized List<Clip> clips() {
        return new ArrayList<Clip>(clips);
    }

    public synchronized Clip addClip(String from, String text) {
        Clip c = new Clip();
        c.id = String.valueOf(++clipSeq);
        c.from = from == null ? "" : from;
        c.text = text;
        c.ts = System.currentTimeMillis();
        clips.addFirst(c);
        while (clips.size() > MAX_CLIPS) clips.removeLast();
        return c;
    }

    public synchronized void clearClips() {
        clips.clear();
    }

    /** Stop a transfer that is moving right now (by file name). */
    public void cancel(String name) {
        cancelNames.put(name, System.currentTimeMillis() + 10000);
        for (UpState st : new ArrayList<UpState>(ups.values())) {
            if (st.name.equals(name) && !st.finished) {
                cancelledUploads.add(st.id);
                Socket sk = st.sock;
                if (sk != null) try { sk.close(); } catch (IOException e) { }
                synchronized (st) {
                    if (!st.finished) {
                        try { st.up.finish(false); } catch (Exception e) { }
                        st.finished = true;
                        st.sha = "";
                    }
                }
                ups.remove(st.id);
            }
        }
    }

    private boolean takeCancel(String name) {
        Long t = cancelNames.get(name);
        if (t == null) return false;
        cancelNames.remove(name);
        return t > System.currentTimeMillis();
    }

    private void housekeeping() {
        long now = System.currentTimeMillis();
        for (UpState st : new ArrayList<UpState>(ups.values())) {
            long idle = now - st.touched;
            if (!st.finished && idle > 300000) {
                synchronized (st) {
                    if (!st.finished) {
                        try { st.up.finish(false); } catch (Exception e) { }
                        st.finished = true;
                    }
                }
                ups.remove(st.id);
            } else if (st.finished && idle > 600000) {
                ups.remove(st.id);
            }
        }
        for (Iterator<Map.Entry<String, Long>> it = cancelNames.entrySet().iterator(); it.hasNext(); ) {
            if (it.next().getValue() < now) it.remove();
        }
    }

    /* ---------------- helpers ---------------- */

    public static List<String> localIps() {
        List<String> wifi = new ArrayList<String>();
        List<String> other = new ArrayList<String>();
        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            while (nis != null && nis.hasMoreElements()) {
                NetworkInterface ni = nis.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                Enumeration<InetAddress> as = ni.getInetAddresses();
                while (as.hasMoreElements()) {
                    InetAddress a = as.nextElement();
                    if (a instanceof Inet4Address && a.isSiteLocalAddress()) {
                        String n = ni.getName() == null ? "" : ni.getName();
                        boolean w = n.startsWith("wlan") || n.startsWith("ap") || n.startsWith("swlan") || n.startsWith("eth");
                        (w ? wifi : other).add(a.getHostAddress());
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        wifi.addAll(other);
        return wifi;
    }

    public static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String hex(byte[] b) {
        char[] d = "0123456789abcdef".toCharArray();
        char[] o = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            o[i * 2] = d[(b[i] >> 4) & 15];
            o[i * 2 + 1] = d[b[i] & 15];
        }
        return new String(o);
    }

    private String randomHex(int bytes) {
        byte[] b = new byte[bytes];
        rnd.nextBytes(b);
        return hex(b);
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c, n = 0;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                int l = sb.length();
                if (l > 0 && sb.charAt(l - 1) == '\r') sb.setLength(l - 1);
                return sb.toString();
            }
            sb.append((char) c);
            if (++n > 16384) throw new IOException("line too long");
        }
        return n == 0 ? null : sb.toString();
    }

    public static String json(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 32) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    public static String cleanName(String n) {
        try { return AirLinkSecurity.validateFilename(n == null ? "file" : n); }
        catch (IllegalArgumentException e) { throw e; }
    }

    private static String cleanLabel(String s, String fallback) {
        if (s == null) return fallback;
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length() && b.length() < 40; i++) {
            char c = s.charAt(i);
            b.append(c < 32 ? ' ' : c);
        }
        String r = b.toString().trim();
        return r.isEmpty() ? fallback : r;
    }

    private static String decode(String s) {
        if (s == null) return null;
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static Map<String, String> query(String q) {
        Map<String, String> m = new HashMap<String, String>();
        if (q == null) return m;
        for (String p : q.split("&")) {
            int e = p.indexOf('=');
            try {
                if (e > 0) m.put(URLDecoder.decode(p.substring(0, e), "UTF-8"), URLDecoder.decode(p.substring(e + 1), "UTF-8"));
            } catch (Exception x) { /* ignore */ }
        }
        return m;
    }

    private static long num(String s, long def) {
        if (s == null) return def;
        try {
            return Long.parseLong(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private void send(OutputStream out, int code, String type, byte[] body) throws IOException {
        String st = code == 200 ? "OK" : code == 204 ? "No Content" : code == 206 ? "Partial Content" : code == 400 ? "Bad Request"
                : code == 401 ? "Unauthorized" : code == 403 ? "Forbidden" : code == 404 ? "Not Found" : code == 409 ? "Conflict"
                : code == 410 ? "Gone" : code == 411 ? "Length Required" : code == 416 ? "Range Not Satisfiable"
                : code == 422 ? "Unprocessable Entity" : code == 429 ? "Too Many Requests" : code == 503 ? "Service Unavailable"
                : code == 507 ? "Insufficient Storage" : "Error";
        String h = "HTTP/1.1 " + code + " " + st + "\r\nContent-Type: " + type + "\r\nContent-Length: " + body.length
                + "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
        out.write(h.getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }

    private void sendJson(OutputStream out, int code, String body) throws IOException {
        send(out, code, "application/json; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
    }

    private void err(OutputStream out, int code, String msg, String errCode) throws IOException {
        sendJson(out, code, "{\"ok\":false,\"error\":" + json(msg) + ",\"code\":" + json(errCode) + "}");
    }

    private boolean blocked(String ip) {
        return !limiter.allow(ip, System.currentTimeMillis());
    }

    private void registerFail(String ip) {
        limiter.failure(ip, System.currentTimeMillis());
    }


    private void touch() {
        lastActivity = System.currentTimeMillis();
    }

    /* ---------------- request handling ---------------- */

    private void handle(Socket s) throws IOException {
        s.setSoTimeout(15000);
        s.setTcpNoDelay(true);
        try {
            s.setSendBufferSize(262144);
            s.setReceiveBufferSize(262144);
        } catch (Exception e) {
            // not important
        }
        InputStream in = new BufferedInputStream(s.getInputStream(), 65536);
        OutputStream out = new BufferedOutputStream(s.getOutputStream(), 65536);
        String line = readLine(in);
        if (line == null || line.isEmpty()) return;
        String[] rl = line.split(" ");
        if (rl.length < 2) return;
        String method = rl[0];
        String target = rl[1];
        Map<String, String> h = new HashMap<String, String>();
        String hl;
        int count = 0;
        while ((hl = readLine(in)) != null && !hl.isEmpty()) {
            int c = hl.indexOf(':');
            if (c > 0) h.put(hl.substring(0, c).trim().toLowerCase(), hl.substring(c + 1).trim());
            if (++count > 80) throw new IOException("too many headers");
        }
        s.setSoTimeout(60000);
        String path = target, qs = null;
        int qi = target.indexOf('?');
        if (qi >= 0) {
            path = target.substring(0, qi);
            qs = target.substring(qi + 1);
        }
        Map<String, String> q = query(qs);
        String ip = s.getInetAddress() == null ? "?" : s.getInetAddress().getHostAddress();
        touch();

        if (method.equals("GET") && (path.equals("/") || path.equals("/index.html"))) {
            InputStream p = host.page();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = p.read(b)) > 0) bo.write(b, 0, n);
            p.close();
            send(out, 200, "text/html; charset=utf-8", bo.toByteArray());
            return;
        }
        if (path.equals("/favicon.ico")) {
            send(out, 204, "image/x-icon", new byte[0]);
            return;
        }
        if (method.equals("POST") && path.equals("/api/auth")) {
            doAuth(out, h, ip);
            return;
        }

        String token = h.get("x-token");
        if (token == null) token = q.get("t");
        Session ses = token == null ? null : sessions.get(token);
        if (ses == null) {
            err(out, 401, "Session expired. Connect again.", "auth");
            return;
        }
        ses.lastSeen = System.currentTimeMillis();

        if (method.equals("GET") && path.equals("/api/ping")) {
            sendJson(out, 200, "{\"ok\":true,\"v\":" + PROTO + ",\"device\":" + json(host.deviceName()) + ",\"free\":" + host.freeSpace() + "}");
        } else if (method.equals("GET") && path.equals("/api/list")) {
            StringBuilder b = new StringBuilder("{\"ok\":true,\"files\":[");
            boolean first = true;
            for (Item it : host.shared()) {
                if (!first) b.append(',');
                first = false;
                b.append("{\"id\":").append(json(it.id)).append(",\"name\":").append(json(it.name)).append(",\"size\":").append(it.size).append('}');
            }
            sendJson(out, 200, b.append("]}").toString());
        } else if (method.equals("GET") && path.startsWith("/f/")) {
            Item found = find(path.substring(3));
            if (found == null) {
                err(out, 404, "File not found", "none");
                return;
            }
            sendFile(out, found, h.get("range"));
        } else if (method.equals("GET") && path.startsWith("/api/hash/")) {
            Item found = find(path.substring(10));
            if (found == null) {
                err(out, 404, "File not found", "none");
                return;
            }
            sendJson(out, 200, "{\"ok\":true,\"sha256\":" + json(hashOf(found)) + "}");
        } else if (method.equals("GET") && path.equals("/zip")) {
            sendZip(out);
        } else if (method.equals("POST") && path.equals("/upload")) {
            receive(s, in, out, h);
        } else if (method.equals("POST") && path.equals("/api/upload-finish")) {
            finishUpload(out, h);
        } else if (method.equals("GET") && path.equals("/api/upload-status")) {
            String uid = q.get("id");
            UpState st = uid == null ? null : ups.get(uid);
            if (st == null || st.finished) err(out, 404, "No partial file", "none");
            else sendJson(out, 200, "{\"ok\":true,\"received\":" + st.received + "}");
        } else if (method.equals("GET") && path.equals("/api/clips")) {
            StringBuilder b = new StringBuilder("{\"ok\":true,\"clips\":[");
            boolean first = true;
            for (Clip c : clips()) {
                if (!first) b.append(',');
                first = false;
                b.append("{\"id\":").append(json(c.id)).append(",\"from\":").append(json(c.from)).append(",\"text\":").append(json(c.text)).append(",\"ts\":").append(c.ts).append('}');
            }
            sendJson(out, 200, b.append("]}").toString());
        } else if (method.equals("POST") && path.equals("/api/clip")) {
            long len = num(h.get("content-length"), -1);
            if (len < 0 || len > MAX_CLIP_BYTES) {
                err(out, 400, "Text is too long", "size");
                return;
            }
            byte[] body = new byte[(int) len];
            int got = 0;
            while (got < len) {
                int n = in.read(body, got, (int) len - got);
                if (n < 0) throw new IOException("closed");
                got += n;
            }
            String text = new String(body, StandardCharsets.UTF_8);
            if (text.trim().isEmpty()) {
                err(out, 400, "Nothing to send", "empty");
                return;
            }
            Clip c = addClip(cleanLabel(decode(h.get("x-from")), ses.name), text);
            try { host.onClip(c); } catch (Throwable e) { }
            sendJson(out, 200, "{\"ok\":true,\"id\":" + json(c.id) + "}");
        } else if (method.equals("POST") && path.equals("/api/logout")) {
            sessions.remove(ses.token);
            host.onSessions();
            sendJson(out, 200, "{\"ok\":true}");
        } else {
            err(out, 404, "Not found", "none");
        }
    }

    private Item find(String id) {
        for (Item it : host.shared()) if (it.id.equals(id)) return it;
        return null;
    }

    private void doAuth(OutputStream out, Map<String, String> h, String ip) throws IOException {
        long now = System.currentTimeMillis();
        if (blocked(ip)) {
            err(out, 429, "Too many authentication attempts. Wait before trying again.", "locked");
            return;
        }
        String cid = h.get("x-client-id");
        if (cid == null || !cid.matches("[A-Za-z0-9_\\-]{6,64}")) cid = ip;
        String suppliedSecret = h.get("x-device-secret");
        String knownSecret = deviceSecrets.get(cid);
        boolean returningDevice = knownSecret != null && suppliedSecret != null && MessageDigest.isEqual(
                knownSecret.getBytes(StandardCharsets.UTF_8), suppliedSecret.getBytes(StandardCharsets.UTF_8));
        if (!returningDevice && !pairing.matches(h.get("x-key"), now)) {
            registerFail(ip);
            err(out, 403, "Pairing code is wrong, expired, or already used", "code");
            return;
        }
        String name = cleanLabel(decode(h.get("x-client-name")), "Computer");
        if (!returningDevice && askApproval) {
            Object lock = approvalLocks.get(cid);
            if (lock == null) {
                Object fresh = new Object(); Object prev = approvalLocks.putIfAbsent(cid, fresh); lock = prev == null ? fresh : prev;
            }
            synchronized (lock) {
                boolean ok;
                try { ok = host.approve(name, ip, cid); } catch (Throwable e) { ok = false; }
                if (!ok) { err(out, 403, "The phone did not allow this device", "denied"); return; }
            }
        }
        if (!returningDevice && !pairing.consume(h.get("x-key"), System.currentTimeMillis())) {
            registerFail(ip);
            err(out, 403, "Pairing code has already been used", "code");
            return;
        }
        limiter.success(ip);
        trusted.add(cid);
        String deviceSecret = knownSecret;
        if (deviceSecret == null) { deviceSecret = randomHex(32); deviceSecrets.put(cid, deviceSecret); }
        for (Session old : new ArrayList<Session>(sessions.values())) if (old.clientId.equals(cid)) sessions.remove(old.token);
        while (sessions.size() >= MAX_SESSIONS) {
            Session oldest = null;
            for (Session x : sessions.values()) if (oldest == null || x.created < oldest.created) oldest = x;
            if (oldest == null) break; sessions.remove(oldest.token);
        }
        Session session = new Session();
        session.id = randomHex(4); session.token = randomHex(16); session.clientId = cid;
        session.name = name; session.ip = ip; session.created = session.lastSeen = now;
        sessions.put(session.token, session);
        trustedDevices.put(cid, session);
        try { host.onSessions(); } catch (Throwable ignored) { }
        sendJson(out, 200, "{\"ok\":true,\"v\":" + PROTO + ",\"token\":" + json(session.token)
                + ",\"deviceSecret\":" + json(deviceSecret) + ",\"sid\":" + json(session.id)
                + ",\"device\":" + json(host.deviceName()) + "}");
    }

    private String hashOf(Item it) throws IOException {
        String ck = it.id + ":" + it.size;
        String c = hashCache.get(ck);
        if (c != null) return c;
        active.incrementAndGet();
        try {
            MessageDigest md = sha256();
            InputStream is = host.open(it);
            try {
                byte[] buf = new byte[65536];
                int n;
                while ((n = is.read(buf)) > 0) {
                    md.update(buf, 0, n);
                    touch();
                }
            } finally {
                try { is.close(); } catch (IOException e) { }
            }
            String r = hex(md.digest());
            hashCache.put(ck, r);
            return r;
        } finally {
            active.decrementAndGet();
        }
    }

    private static void skipFully(InputStream is, long n) throws IOException {
        byte[] sink = null;
        while (n > 0) {
            long k = is.skip(n);
            if (k <= 0) {
                if (sink == null) sink = new byte[65536];
                int r = is.read(sink, 0, (int) Math.min(sink.length, n));
                if (r < 0) throw new IOException("file ended");
                k = r;
            }
            n -= k;
        }
    }

    private static String contentType(String name) {
        String type = URLConnection.guessContentTypeFromName(name);
        return type == null ? "application/octet-stream" : type;
    }

    private static String attachment(String name) throws IOException {
        String enc = URLEncoder.encode(name, "UTF-8").replace("+", "%20");
        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            ascii.append(c >= 32 && c < 127 && c != '"' && c != '\\' ? c : '_');
        }
        return "Content-Disposition: attachment; filename=\"" + ascii + "\"; filename*=UTF-8''" + enc + "\r\n";
    }

    private void sendFile(OutputStream out, Item it, String range) throws IOException {
        long size = it.size, start = 0, end = size - 1;
        boolean partial = false;
        if (range != null && size > 0 && range.startsWith("bytes=") && range.indexOf(',') < 0) {
            String spec = range.substring(6).trim();
            int dash = spec.indexOf('-');
            if (dash >= 0) {
                String a = spec.substring(0, dash).trim(), b = spec.substring(dash + 1).trim();
                long x = -1, y = -1;
                if (a.isEmpty()) {
                    long suffix = num(b, -1);
                    if (suffix > 0) {
                        x = Math.max(0, size - suffix);
                        y = size - 1;
                    }
                } else {
                    x = num(a, -1);
                    y = b.isEmpty() ? size - 1 : Math.min(num(b, -1), size - 1);
                }
                if (x < 0 || y < x || x >= size) {
                    String h = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */" + size + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    out.write(h.getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                    return;
                }
                start = x;
                end = y;
                partial = true;
            }
        }
        InputStream is = host.open(it);
        active.incrementAndGet();
        try {
            skipFully(is, start);
            StringBuilder h = new StringBuilder(partial ? "HTTP/1.1 206 Partial Content\r\n" : "HTTP/1.1 200 OK\r\n");
            h.append("Content-Type: ").append(contentType(it.name)).append("\r\n");
            if (size >= 0) h.append("Content-Length: ").append(end - start + 1).append("\r\n");
            if (partial) h.append("Content-Range: bytes ").append(start).append('-').append(end).append('/').append(size).append("\r\n");
            if (size >= 0) h.append("Accept-Ranges: bytes\r\n");
            h.append(attachment(it.name));
            h.append("Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n");
            out.write(h.toString().getBytes(StandardCharsets.ISO_8859_1));
            byte[] buf = new byte[65536];
            long done = start, last = 0;
            long stop = size >= 0 ? end + 1 : Long.MAX_VALUE;
            while (done < stop) {
                int want = (int) Math.min(buf.length, stop - done);
                int n = is.read(buf, 0, want);
                if (n <= 0) break;
                out.write(buf, 0, n);
                done += n;
                long now = System.currentTimeMillis();
                if (now - last > 400) {
                    last = now;
                    touch();
                    if (takeCancel(it.name)) throw new IOException("cancelled");
                    host.onProgress(it.name, done, size, false);
                }
            }
            out.flush();
            host.onProgress(it.name, done, size, false);
        } finally {
            active.decrementAndGet();
            try { is.close(); } catch (IOException e) { }
        }
    }

    private void sendZip(OutputStream out) throws IOException {
        List<Item> list = host.shared();
        if (list.isEmpty()) {
            err(out, 404, "No files to send", "none");
            return;
        }
        String h = "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n" + attachment("AirLink-files.zip")
                + "Cache-Control: no-store\r\nConnection: close\r\n\r\n";
        out.write(h.getBytes(StandardCharsets.ISO_8859_1));
        final OutputStream raw = out;
        ZipOutputStream zo = new ZipOutputStream(new OutputStream() {
            public void write(int b) throws IOException {
                raw.write(b);
            }

            public void write(byte[] b, int o, int l) throws IOException {
                raw.write(b, o, l);
            }

            public void flush() throws IOException {
                raw.flush();
            }

            public void close() {
                // keep the socket open
            }
        });
        zo.setLevel(1);
        Set<String> used = new HashSet<String>();
        active.incrementAndGet();
        try {
            for (Item it : list) {
                String nm = it.name, stem = nm, ext = "";
                int dot = nm.lastIndexOf('.');
                if (dot > 0) {
                    stem = nm.substring(0, dot);
                    ext = nm.substring(dot);
                }
                int k = 1;
                while (!used.add(nm)) nm = stem + " (" + (k++) + ")" + ext;
                zo.putNextEntry(new ZipEntry(nm));
                InputStream is = host.open(it);
                try {
                    byte[] buf = new byte[65536];
                    long done = 0, last = 0;
                    int n;
                    while ((n = is.read(buf)) > 0) {
                        zo.write(buf, 0, n);
                        done += n;
                        long now = System.currentTimeMillis();
                        if (now - last > 400) {
                            last = now;
                            touch();
                            if (takeCancel("AirLink-files.zip")) throw new IOException("cancelled");
                            host.onProgress("AirLink-files.zip", done, -1, false);
                        }
                    }
                } finally {
                    try { is.close(); } catch (IOException e) { }
                }
                zo.closeEntry();
            }
            zo.finish();
            out.flush();
            host.onProgress("AirLink-files.zip", 1, 1, false);
        } finally {
            active.decrementAndGet();
        }
    }

    /* ---------------- uploads ---------------- */

    private void receive(Socket sock, InputStream in, OutputStream out, Map<String, String> h) throws IOException {
        long len = num(h.get("content-length"), -1);
        if (len < 0) {
            err(out, 411, "Content-Length needed", "length");
            return;
        }
        String raw = h.get("x-filename");
        String name;
        try { name = AirLinkSecurity.validateFilename(raw == null ? "file" : decode(raw)); }
        catch (IllegalArgumentException badName) { err(out, 400, "Invalid filename or path traversal", "filename"); return; }
        String uid = h.get("x-upload-id");
        boolean legacy = uid == null;
        if (legacy) uid = "L" + randomHex(8);
        else if (!uid.matches("[A-Za-z0-9_\\-]{8,64}")) {
            err(out, 400, "Bad upload id", "id");
            return;
        }
        if (cancelledUploads.contains(uid)) {
            err(out, 410, "Cancelled on the phone", "cancelled");
            return;
        }
        long offset = legacy ? 0 : num(h.get("x-offset"), 0);
        long total = legacy ? len : num(h.get("x-total"), -1);
        try { AirLinkSecurity.validateUpload(offset, len, total, AirLinkSecurity.MAX_UPLOAD_BYTES); }
        catch (IllegalArgumentException badSize) { err(out, 413, "Upload exceeds the allowed size or has invalid offsets", "size"); return; }
        UpState st = ups.get(uid);
        if (st == null) {
            if (offset > 0) {
                err(out, 409, "The phone lost the partial file. Start again.", "restart");
                return;
            }
            long free = host.freeSpace();
            if (free >= 0 && total > free - (8L << 20)) {
                err(out, 507, "Not enough space on the phone", "space");
                return;
            }
            UpState fresh = new UpState();
            fresh.id = uid;
            fresh.name = name;
            fresh.total = total;
            fresh.legacy = legacy;
            fresh.md = sha256();
            fresh.up = host.createUpload(name, total);
            fresh.os = fresh.up.stream();
            fresh.touched = System.currentTimeMillis();
            UpState prev = ups.putIfAbsent(uid, fresh);
            if (prev != null) {
                try { fresh.up.finish(false); } catch (Exception e) { }
                st = prev;
            } else {
                st = fresh;
            }
        }
        Socket old = st.sock;
        if (old != null && old != sock) {
            try { old.close(); } catch (IOException e) { }
        }
        active.incrementAndGet();
        try {
            synchronized (st) {
                if (st.finished) {
                    sendJson(out, 200, "{\"ok\":true,\"done\":true,\"received\":" + st.total + ",\"sha256\":" + json(st.sha) + "}");
                    return;
                }
                if (st.total != total) {
                    err(out, 400, "The file size changed", "size");
                    return;
                }
                if (offset != st.received) {
                    sendJson(out, 409, "{\"ok\":false,\"error\":\"Out of step\",\"code\":\"offset\",\"received\":" + st.received + "}");
                    return;
                }
                st.sock = sock;
                boolean ok = false;
                try {
                    byte[] buf = new byte[65536];
                    long got = 0, last = 0;
                    while (got < len) {
                        int n = in.read(buf, 0, (int) Math.min(buf.length, len - got));
                        if (n < 0) throw new IOException("connection closed");
                        st.os.write(buf, 0, n);
                        st.md.update(buf, 0, n);
                        got += n;
                        st.received += n;
                        long now = System.currentTimeMillis();
                        st.touched = now;
                        if (now - last > 400) {
                            last = now;
                            touch();
                            host.onProgress(st.name, st.received, st.total, true);
                        }
                    }
                    ok = true;
                } finally {
                    st.sock = null;
                    if (!ok && st.legacy) {
                        try { st.up.finish(false); } catch (Exception e) { }
                        st.finished = true;
                        ups.remove(st.id);
                    }
                }
                host.onProgress(st.name, st.received, st.total, true);
                if (st.legacy) {
                    st.sha = hex(st.md.digest());
                    st.where = st.up.finish(true);
                    st.finished = true;
                    ups.remove(st.id);
                    host.onReceived(st.name, st.total, st.where, st.sha);
                    sendJson(out, 200, "{\"ok\":true,\"done\":true,\"name\":" + json(st.name) + ",\"size\":" + st.total + ",\"sha256\":" + json(st.sha) + "}");
                } else {
                    sendJson(out, 200, "{\"ok\":true,\"received\":" + st.received + "}");
                }
            }
        } finally {
            active.decrementAndGet();
        }
    }

    private void finishUpload(OutputStream out, Map<String, String> h) throws IOException {
        String uid = h.get("x-upload-id");
        UpState st = uid == null ? null : ups.get(uid);
        if (st == null) {
            boolean gone = uid != null && cancelledUploads.contains(uid);
            err(out, gone ? 410 : 404, gone ? "Cancelled on the phone" : "Upload not found", gone ? "cancelled" : "none");
            return;
        }
        synchronized (st) {
            if (st.finished) {
                if (st.sha.isEmpty()) err(out, 410, "Cancelled on the phone", "cancelled");
                else sendJson(out, 200, "{\"ok\":true,\"done\":true,\"sha256\":" + json(st.sha) + "}");
                return;
            }
            if (st.received != st.total) {
                sendJson(out, 409, "{\"ok\":false,\"error\":\"File is not complete\",\"code\":\"offset\",\"received\":" + st.received + "}");
                return;
            }
            String sha = hex(st.md.digest());
            String want = h.get("x-sha256");
            if (want != null && !want.trim().equalsIgnoreCase(sha)) {
                try { st.up.finish(false); } catch (Exception e) { }
                st.finished = true;
                ups.remove(st.id);
                err(out, 422, "The file arrived damaged (checksum mismatch)", "hash");
                return;
            }
            st.where = st.up.finish(true);
            st.sha = sha;
            st.finished = true;
            st.touched = System.currentTimeMillis();
            host.onReceived(st.name, st.total, st.where, sha);
            sendJson(out, 200, "{\"ok\":true,\"done\":true,\"name\":" + json(st.name) + ",\"size\":" + st.total + ",\"sha256\":" + json(sha) + "}");
        }
    }
}
