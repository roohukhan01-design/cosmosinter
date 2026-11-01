package com.roohu.airlink;

import android.app.Activity;
import android.content.ClipData;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import androidx.activity.result.ActivityResult;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@CapacitorPlugin(name = "LanShare")
public class LanSharePlugin extends Plugin implements LanServer.Host {

    private static class Approval {
        String id, name, ip;
        final CountDownLatch latch = new CountDownLatch(1);
        volatile boolean allow;
    }

    private interface Op<T> {
        T run(String token) throws IOException;
    }

    private LanServer server;
    private final Beacon beacon = new Beacon();
    private final ExecutorService peerPool = Executors.newFixedThreadPool(3);
    private final SecureRandom rnd = new SecureRandom();
    private String key = "";
    private int port = 0;
    private int seq = 0;
    private boolean askApproval = true;
    private int idleMinutes = 0;
    private long lastNote = 0;
    private final List<LanServer.Item> items = new CopyOnWriteArrayList<LanServer.Item>();
    private final Map<String, String> tokens = new ConcurrentHashMap<String, String>();
    private final Set<String> cancelled = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
    private final Map<String, Approval> approvals = new ConcurrentHashMap<String, Approval>();
    private final List<String> pendingClips = new CopyOnWriteArrayList<String>();

    /* ---------------- this phone as the sharing side ---------------- */

    private boolean isOn() {
        return server != null && server.isRunning();
    }

    private Map<String, String> savedTrustedSecrets() {
        Map<String, String> out = new HashMap<String, String>();
        try {
            Map<String, ?> all = getContext().getSharedPreferences("airlink_trusted", Context.MODE_PRIVATE).getAll();
            for (Map.Entry<String, ?> entry : all.entrySet()) if (entry.getValue() instanceof String) out.put(entry.getKey(), (String) entry.getValue());
        } catch (Exception ignored) { }
        return out;
    }

    private void persistTrustedSecrets() {
        try {
            android.content.SharedPreferences prefs = getContext().getSharedPreferences("airlink_trusted", Context.MODE_PRIVATE);
            android.content.SharedPreferences.Editor edit = prefs.edit(); edit.clear();
            if (server != null) for (Map.Entry<String, String> entry : server.exportTrustedSecrets().entrySet()) edit.putString(entry.getKey(), entry.getValue());
            edit.apply();
        } catch (Exception ignored) { }
    }

    private JSObject info() {
        JSObject r = new JSObject();
        r.put("running", isOn());
        r.put("port", port);
        r.put("tlsPort", server == null ? 0 : server.tlsPort());
        r.put("fingerprint", server == null ? "" : server.tlsFingerprint());
        r.put("key", key);
        r.put("codeExpiresAt", server == null ? 0 : server.pairingExpiresAt());
        JSArray ips = new JSArray();
        for (String ip : LanServer.localIps()) ips.put(ip);
        r.put("ips", ips);
        r.put("device", Build.MODEL);
        r.put("approve", askApproval);
        r.put("idleMinutes", idleMinutes);
        r.put("version", LanServer.PROTO);
        return r;
    }

    private JSObject files() {
        JSObject r = new JSObject();
        JSArray arr = new JSArray();
        for (LanServer.Item it : items) {
            JSObject o = new JSObject();
            o.put("id", it.id);
            o.put("name", it.name);
            o.put("size", it.size);
            arr.put(o);
        }
        r.put("files", arr);
        return r;
    }

    private JSObject devicesObj() {
        JSObject r = new JSObject();
        JSArray arr = new JSArray();
        if (server != null) {
            for (LanServer.Session s : server.trustedDevices()) {
                JSObject o = new JSObject();
                o.put("id", s.id);
                o.put("name", s.name);
                o.put("ip", s.ip);
                o.put("since", s.created);
                arr.put(o);
            }
        }
        r.put("devices", arr);
        return r;
    }

    private JSObject clipObj(LanServer.Clip c) {
        JSObject o = new JSObject();
        o.put("id", c.id);
        o.put("from", c.from);
        o.put("text", c.text);
        o.put("ts", c.ts);
        return o;
    }

    private JSObject clipsObj() {
        JSObject r = new JSObject();
        JSArray arr = new JSArray();
        if (server != null) {
            for (LanServer.Clip c : server.clips()) arr.put(clipObj(c));
        }
        r.put("clips", arr);
        return r;
    }

    private String statusText() {
        int n = server == null ? 0 : server.sessions().size();
        return n > 0 ? "Sharing is on \u00b7 " + n + (n == 1 ? " device" : " devices") + " connected" : "Sharing is on";
    }

    @PluginMethod
    public void start(PluginCall call) {
        int want = call.getInt("port", 8080);
        askApproval = call.getBoolean("approve", true);
        idleMinutes = call.getInt("idleMinutes", 0);
        stopAll(false);
        server = new LanServer(this, savedTrustedSecrets());
        key = String.format("%06d", rnd.nextInt(1000000));
        int p = -1;
        for (int t = 0; t < 15 && p < 0; t++) {
            try {
                p = server.start(want + t, key, askApproval, idleMinutes);
            } catch (IOException e) {
                p = -1;
            }
        }
        if (p < 0) {
            call.reject("Could not open a port");
            return;
        }
        port = p;
        for (String t : pendingClips) server.addClip("This phone", t);
        pendingClips.clear();
        beacon.start(server.tlsPort(), port, server.tlsFingerprint(), Build.MODEL);
        ShareService.setStopper(new Runnable() {
            public void run() {
                stopAll(true);
            }
        });
        ShareService.start(getContext(), "Sharing is on");
        call.resolve(info());
    }

    private void stopAll(boolean tellApp) {
        beacon.stop();
        for (Approval a : approvals.values()) {
            a.allow = false;
            a.latch.countDown();
        }
        approvals.clear();
        if (server != null) server.stop();
        ShareService.stop(getContext());
        if (tellApp) notifyListeners("stopped", info());
    }

    @PluginMethod
    public void stop(PluginCall call) {
        stopAll(false);
        call.resolve(info());
    }

    @PluginMethod
    public void status(PluginCall call) {
        call.resolve(info());
    }

    @PluginMethod
    public void devices(PluginCall call) {
        call.resolve(devicesObj());
    }

    @PluginMethod
    public void revokeDevice(PluginCall call) {
        String id = call.getString("id");
        if (server != null && id != null) server.revoke(id);
        call.resolve(devicesObj());
    }

    @PluginMethod
    public void rotateCode(PluginCall call) {
        if (isOn()) {
            key = String.format("%06d", rnd.nextInt(1000000));
            server.setKey(key);
        }
        call.resolve(info());
    }

    @PluginMethod
    public void respondApproval(PluginCall call) {
        Approval a = approvals.get(call.getString("rid", ""));
        if (a != null) {
            a.allow = call.getBoolean("allow", false);
            a.latch.countDown();
        }
        call.resolve();
    }

    @PluginMethod
    public void pendingApprovals(PluginCall call) {
        JSArray arr = new JSArray();
        for (Approval a : approvals.values()) {
            JSObject o = new JSObject();
            o.put("rid", a.id);
            o.put("name", a.name);
            o.put("ip", a.ip);
            arr.put(o);
        }
        JSObject r = new JSObject();
        r.put("pending", arr);
        call.resolve(r);
    }

    @PluginMethod
    public void listClips(PluginCall call) {
        call.resolve(clipsObj());
    }

    @PluginMethod
    public void addClip(PluginCall call) {
        String text = call.getString("text", "");
        if (text != null && !text.trim().isEmpty()) {
            if (isOn()) server.addClip("This phone", text);
            else pendingClips.add(text);
        }
        call.resolve(clipsObj());
    }

    @PluginMethod
    public void clearClips(PluginCall call) {
        if (server != null) server.clearClips();
        pendingClips.clear();
        call.resolve(clipsObj());
    }

    /** Stop a transfer that is moving right now. */
    @PluginMethod
    public void cancel(PluginCall call) {
        String name = call.getString("name");
        if (name != null) {
            cancelled.add(name);
            if (server != null) server.cancel(name);
        }
        call.resolve();
    }

    @PluginMethod
    public void pickFiles(PluginCall call) {
        startActivityForResult(call, openIntent(), "pickResult");
    }

    private Intent openIntent() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        return i;
    }

    private List<Uri> urisOf(ActivityResult result) {
        List<Uri> list = new ArrayList<Uri>();
        Intent d = result.getData();
        if (result.getResultCode() == Activity.RESULT_OK && d != null) {
            ClipData cd = d.getClipData();
            if (cd != null) {
                for (int k = 0; k < cd.getItemCount(); k++) {
                    Uri u = cd.getItemAt(k).getUri();
                    if (u != null) list.add(u);
                }
            } else if (d.getData() != null) {
                list.add(d.getData());
            }
        }
        return list;
    }

    @ActivityCallback
    private void pickResult(PluginCall call, ActivityResult result) {
        if (call == null) return;
        for (Uri u : urisOf(result)) addItem(u);
        call.resolve(files());
    }

    private void addItem(Uri u) {
        LanServer.Item it = describe(u);
        it.id = String.valueOf(++seq);
        items.add(it);
    }

    /** Files or text shared into AirLink from another app (Android share sheet). */
    @SuppressWarnings({"deprecation", "unchecked"})
    public void ingest(Intent intent) {
        if (intent == null) return;
        String act = intent.getAction();
        boolean one = Intent.ACTION_SEND.equals(act);
        if (!one && !Intent.ACTION_SEND_MULTIPLE.equals(act)) return;
        List<Uri> uris = new ArrayList<Uri>();
        try {
            if (one) {
                Uri u = (Uri) intent.getParcelableExtra(Intent.EXTRA_STREAM);
                if (u != null) uris.add(u);
            } else {
                ArrayList<Uri> l = intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
                if (l != null) uris.addAll(l);
            }
        } catch (Exception e) {
            // unreadable extras
        }
        int count = 0;
        for (Uri u : uris) {
            try {
                addItem(u);
                count++;
            } catch (Exception e) {
                // skip this one
            }
        }
        boolean text = false;
        String t = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (uris.isEmpty() && t != null && !t.trim().isEmpty()) {
            if (isOn()) server.addClip("This phone", t);
            else pendingClips.add(t);
            text = true;
        }
        intent.setAction(null);
        if (count > 0 || text) {
            JSObject o = new JSObject();
            o.put("count", count);
            o.put("text", text);
            notifyListeners("shared", o);
        }
    }

    @PluginMethod
    public void removeShared(PluginCall call) {
        String id = call.getString("id");
        for (LanServer.Item it : items) {
            if (it.id.equals(id)) items.remove(it);
        }
        call.resolve(files());
    }

    @PluginMethod
    public void clearShared(PluginCall call) {
        items.clear();
        call.resolve(files());
    }

    @PluginMethod
    public void listShared(PluginCall call) {
        call.resolve(files());
    }

    private LanServer.Item describe(Uri uri) {
        String name = "file";
        long size = -1;
        Cursor c = null;
        try {
            c = getContext().getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                int si = c.getColumnIndex(OpenableColumns.SIZE);
                if (ni >= 0 && !c.isNull(ni)) name = c.getString(ni);
                if (si >= 0 && !c.isNull(si)) size = c.getLong(si);
            }
        } catch (Exception e) {
            // keep defaults
        } finally {
            if (c != null) c.close();
        }
        try {
            getContext().getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (Exception e) {
            // not needed for the current session
        }
        LanServer.Item it = new LanServer.Item();
        it.name = LanServer.cleanName(name);
        it.size = size;
        it.ref = uri;
        return it;
    }

    @Override
    protected void handleOnDestroy() {
        stopAll(false);
        peerPool.shutdownNow();
    }

    /* ---------------- this phone talking to another phone ---------------- */

    private String clientId() {
        SharedPreferences sp = getContext().getSharedPreferences("airlink", Context.MODE_PRIVATE);
        String id = sp.getString("cid", null);
        if (id == null) {
            id = UUID.randomUUID().toString().replace("-", "");
            sp.edit().putString("cid", id).apply();
        }
        return id;
    }

    private String tokenFor(String host, int p, String k, boolean force) throws IOException {
        String ck = host + ":" + p + ":" + k;
        if (!force) {
            String t = tokens.get(ck);
            if (t != null) return t;
        }
        String cid = clientId();
        android.content.SharedPreferences sp = getContext().getSharedPreferences("airlink", Context.MODE_PRIVATE);
        String savedSecret = sp.getString("device_secret_" + host + "_" + cid, null);
        if (savedSecret != null) LanClient.setDeviceSecret(host, p, cid, savedSecret);
        String t = LanClient.auth(host, p, k, cid, Build.MODEL);
        String freshSecret = LanClient.deviceSecretFor(host, p, cid);
        if (freshSecret != null) sp.edit().putString("device_secret_" + host + "_" + cid, freshSecret).apply();
        tokens.put(ck, t);
        return t;
    }

    private <T> T withAuth(String host, int p, String k, Op<T> op) throws IOException {
        String t = tokenFor(host, p, k, false);
        try {
            return op.run(t);
        } catch (LanClient.HttpError e) {
            if (!e.isAuth()) throw e;
            return op.run(tokenFor(host, p, k, true));
        }
    }

    @PluginMethod
    public void scan(final PluginCall call) {
        new Thread(new Runnable() {
            public void run() {
                WifiManager.MulticastLock ml = null;
                try {
                    WifiManager wm = (WifiManager) getContext().getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                    if (wm != null) {
                        ml = wm.createMulticastLock("airlink-scan");
                        ml.setReferenceCounted(false);
                        ml.acquire();
                    }
                } catch (Exception e) {
                    ml = null;
                }
                try {
                    List<Beacon.Peer> ps = Beacon.scan(4500, new HashSet<String>(LanServer.localIps()));
                    JSArray arr = new JSArray();
                    for (Beacon.Peer p : ps) {
                        JSObject o = new JSObject();
                        o.put("name", p.name);
                        o.put("ip", p.ip);
                        o.put("port", p.port);
                        o.put("httpPort", p.httpPort);
                        o.put("fingerprint", p.fingerprint);
                        arr.put(o);
                    }
                    JSObject r = new JSObject();
                    r.put("peers", arr);
                    call.resolve(r);
                } catch (Exception e) {
                    call.reject("Could not search: " + e.getMessage());
                } finally {
                    try {
                        if (ml != null && ml.isHeld()) ml.release();
                    } catch (Exception e) {
                        // ignore
                    }
                }
            }
        }, "airlink-scan").start();
    }

    @PluginMethod
    public void peerList(final PluginCall call) {
        final String host = call.getString("host");
        final int p = call.getInt("tlsPort", call.getInt("port", 8080));
        final String fp = call.getString("fingerprint");
        final String k = call.getString("key");
        if (host == null || k == null) {
            call.reject("Enter the address and the code");
            return;
        }
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (fp != null && !fp.isEmpty()) LanClient.pinTls(host, p, fp); else LanClient.clearTlsPin(host, p);
                    String[] both = withAuth(host, p, k, new Op<String[]>() {
                        public String[] run(String token) throws IOException {
                            String ping = LanClient.getText(host, p, token, "/api/ping");
                            String list = LanClient.getText(host, p, token, "/api/list");
                            return new String[]{ping, list};
                        }
                    });
                    JSObject r = new JSObject(both[1]);
                    r.put("device", new JSObject(both[0]).optString("device", "Phone"));
                    call.resolve(r);
                } catch (Exception e) {
                    String m = e.getMessage();
                    call.reject(m == null ? "Could not connect" : m);
                }
            }
        }, "airlink-peer-list").start();
    }

    @PluginMethod
    public void peerDownload(PluginCall call) {
        final String host = call.getString("host");
        final int p = call.getInt("tlsPort", call.getInt("port", 8080));
        final String fp = call.getString("fingerprint");
        final String k = call.getString("key");
        final String id = call.getString("id");
        final String name = LanServer.cleanName(call.getString("name"));
        if (host == null || k == null || id == null) {
            call.reject("Missing information");
            return;
        }
        if (fp != null && !fp.isEmpty()) LanClient.pinTls(host, p, fp); else LanClient.clearTlsPin(host, p);
        cancelled.remove(name);
        peerPool.execute(new Runnable() {
            public void run() {
                downloadJob(host, p, k, id, name);
            }
        });
        JSObject r = new JSObject();
        r.put("queued", true);
        call.resolve(r);
    }

    private LanClient.Cancel cancelOf(final String name) {
        return new LanClient.Cancel() {
            public boolean is() {
                return cancelled.contains(name);
            }
        };
    }

    private static void pause(long ms) throws IOException {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            throw new IOException("Interrupted");
        }
    }

    private void downloadJob(final String host, final int p, final String k, final String id, final String name) {
        LanServer.Upload up = null;
        boolean ok = false;
        String where = "";
        String sha = "";
        final LanClient.DownloadState st = new LanClient.DownloadState();
        try {
            up = createUpload(name, -1);
            OutputStream os = up.stream();
            int fails = 0;
            boolean reauthed = false;
            while (true) {
                long before = st.done;
                try {
                    String tok = tokenFor(host, p, k, false);
                    LanClient.download(host, p, tok, id, os, st, new LanClient.Progress() {
                        public void on(long done, long total) {
                            onProgress(name, done, total >= 0 ? total : done, true);
                        }
                    }, cancelOf(name));
                    break;
                } catch (LanClient.CancelledException e) {
                    throw e;
                } catch (LanClient.HttpError e) {
                    if (e.isAuth() && !reauthed) {
                        reauthed = true;
                        tokenFor(host, p, k, true);
                        continue;
                    }
                    if (e.status == 503 && ++fails <= 6) {
                        pause(1500L * fails);
                        continue;
                    }
                    throw e;
                } catch (IOException e) {
                    if (st.done > before) fails = 0;
                    if (++fails > 6) throw e;
                    pause(1000L * fails);
                }
            }
            sha = LanServer.hex(st.md.digest());
            phase(name, "verify");
            try {
                String want = withAuth(host, p, k, new Op<String>() {
                    public String run(String token) throws IOException {
                        return LanClient.remoteHash(host, p, token, id);
                    }
                });
                if (!want.equalsIgnoreCase(sha)) throw new IOException("The file arrived damaged. Please try again.");
            } catch (LanClient.HttpError e) {
                if (e.status != 404) throw e;
            }
            ok = true;
        } catch (Exception e) {
            peerError(name, e);
        } finally {
            if (up != null) {
                try {
                    where = up.finish(ok);
                } catch (Exception e) {
                    // ignore
                }
            }
            cancelled.remove(name);
        }
        if (ok) onReceived(name, st.total, where, sha);
    }

    @PluginMethod
    public void pickAndSend(PluginCall call) {
        startActivityForResult(call, openIntent(), "sendResult");
    }

    @ActivityCallback
    private void sendResult(PluginCall call, ActivityResult result) {
        if (call == null) return;
        final String host = call.getString("host");
        final int p = call.getInt("tlsPort", call.getInt("port", 8080));
        final String fp = call.getString("fingerprint");
        final String k = call.getString("key");
        if (host != null) { if (fp != null && !fp.isEmpty()) LanClient.pinTls(host, p, fp); else LanClient.clearTlsPin(host, p); }
        int count = 0;
        if (host != null && k != null) {
            for (final Uri u : urisOf(result)) {
                final LanServer.Item it = describe(u);
                count++;
                cancelled.remove(it.name);
                peerPool.execute(new Runnable() {
                    public void run() {
                        sendOne(host, p, k, u, it);
                    }
                });
            }
        }
        JSObject r = new JSObject();
        r.put("count", count);
        call.resolve(r);
    }

    private String newUploadId() {
        byte[] b = new byte[12];
        rnd.nextBytes(b);
        return LanServer.hex(b);
    }

    private void sendOne(final String host, final int p, final String k, final Uri u, final LanServer.Item it) {
        final String nm = it.name;
        File tmp = null;
        try {
            final ContentResolver cr = getContext().getContentResolver();
            long len = it.size;
            LanClient.Source src;
            if (len < 0) {
                tmp = File.createTempFile("send", ".tmp", getContext().getCacheDir());
                InputStream in = cr.openInputStream(u);
                if (in == null) throw new IOException("Cannot open the file");
                OutputStream o = new FileOutputStream(tmp);
                try {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
                } finally {
                    o.close();
                    in.close();
                }
                len = tmp.length();
                final File f = tmp;
                src = new LanClient.Source() {
                    public InputStream open() throws IOException {
                        return new FileInputStream(f);
                    }
                };
            } else {
                src = new LanClient.Source() {
                    public InputStream open() throws IOException {
                        InputStream in = cr.openInputStream(u);
                        if (in == null) throw new IOException("Cannot open the file");
                        return in;
                    }
                };
            }
            String uid = newUploadId();
            int tries = 0;
            String sha;
            while (true) {
                try {
                    sha = LanClient.upload(host, p, tokenFor(host, p, k, false), nm, src, len, uid, new LanClient.Progress() {
                        public void on(long done, long total) {
                            onProgress(nm, done, total, false);
                        }
                    }, cancelOf(nm));
                    break;
                } catch (LanClient.HttpError e) {
                    if (e.isAuth() && tries++ < 2) {
                        tokenFor(host, p, k, true);
                        continue;
                    }
                    if ("restart".equals(e.code) && tries++ < 2) {
                        uid = newUploadId();
                        continue;
                    }
                    throw e;
                }
            }
            JSObject o = new JSObject();
            o.put("name", nm);
            o.put("sha256", sha);
            notifyListeners("sent", o);
        } catch (Exception e) {
            peerError(nm, e);
        } finally {
            if (tmp != null) tmp.delete();
            cancelled.remove(nm);
        }
    }

    private void peerError(String name, Exception e) {
        JSObject o = new JSObject();
        o.put("name", name);
        boolean c = e instanceof LanClient.CancelledException;
        o.put("cancelled", c);
        o.put("message", c ? "Cancelled" : (e.getMessage() == null ? "Transfer failed" : e.getMessage()));
        notifyListeners("peerError", o);
    }

    private void phase(String name, String ph) {
        JSObject o = new JSObject();
        o.put("name", name);
        o.put("phase", ph);
        notifyListeners("phase", o);
    }

    private void note(String text) {
        long now = System.currentTimeMillis();
        if (now - lastNote > 800) {
            lastNote = now;
            ShareService.update(getContext(), text);
        }
    }

    /* ---------------- LanServer.Host ---------------- */

    public List<LanServer.Item> shared() {
        return new ArrayList<LanServer.Item>(items);
    }

    public InputStream open(LanServer.Item item) throws IOException {
        InputStream is = getContext().getContentResolver().openInputStream((Uri) item.ref);
        if (is == null) throw new IOException("Cannot open file");
        return is;
    }

    public InputStream page() throws IOException {
        return getContext().getAssets().open("pc.html");
    }

    public String deviceName() {
        return Build.MODEL;
    }

    @SuppressWarnings("deprecation")
    public long freeSpace() {
        try {
            File d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            return new StatFs(d.getPath()).getAvailableBytes();
        } catch (Exception e) {
            return -1;
        }
    }

    public void onProgress(String name, long done, long total, boolean incoming) {
        JSObject o = new JSObject();
        o.put("name", name);
        o.put("done", done);
        o.put("total", total);
        o.put("upload", incoming);
        notifyListeners("progress", o);
        if (total > 0) {
            note((incoming ? "Receiving " : "Sending ") + name + " \u00b7 " + (int) Math.min(100, done * 100 / total) + "%");
        } else {
            note((incoming ? "Receiving " : "Sending ") + name);
        }
    }

    public void onReceived(String name, long size, String where, String sha256) {
        JSObject o = new JSObject();
        o.put("name", name);
        o.put("size", size);
        o.put("where", where);
        o.put("sha256", sha256);
        notifyListeners("received", o);
        lastNote = 0;
        ShareService.update(getContext(), "Received " + name);
    }

    public boolean approve(String clientName, String ip, String clientId) {
        Approval a = new Approval();
        a.id = String.valueOf(rnd.nextInt(Integer.MAX_VALUE));
        a.name = clientName;
        a.ip = ip;
        approvals.put(a.id, a);
        JSObject o = new JSObject();
        o.put("rid", a.id);
        o.put("name", clientName);
        o.put("ip", ip);
        notifyListeners("approval", o);
        ShareService.update(getContext(), "Allow " + clientName + "? Open AirLink to answer");
        boolean ok = false;
        try {
            ok = a.latch.await(45, TimeUnit.SECONDS) && a.allow;
        } catch (InterruptedException e) {
            ok = false;
        } finally {
            approvals.remove(a.id);
            JSObject gone = new JSObject();
            gone.put("rid", a.id);
            notifyListeners("approvalDone", gone);
            ShareService.update(getContext(), statusText());
        }
        return ok;
    }

    public void onSessions() {
        persistTrustedSecrets();
        notifyListeners("devices", devicesObj());
        if (isOn()) ShareService.update(getContext(), statusText());
    }

    public void onClip(LanServer.Clip clip) {
        notifyListeners("clip", clipObj(clip));
    }

    public void onIdleStop() {
        stopAll(true);
    }

    public LanServer.Upload createUpload(final String name, long length) throws IOException {
        final Context ctx = getContext();
        String mime = URLConnection.guessContentTypeFromName(name);
        if (mime == null) mime = "application/octet-stream";
        if (Build.VERSION.SDK_INT >= 29) {
            final ContentResolver cr = ctx.getContentResolver();
            ContentValues v = new ContentValues();
            v.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
            v.put(MediaStore.MediaColumns.MIME_TYPE, mime);
            v.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/AirLink");
            v.put(MediaStore.MediaColumns.IS_PENDING, 1);
            final Uri uri = cr.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
            if (uri == null) throw new IOException("Cannot create file");
            final OutputStream os = cr.openOutputStream(uri);
            if (os == null) throw new IOException("Cannot write file");
            return new LanServer.Upload() {
                public OutputStream stream() {
                    return os;
                }

                public String finish(boolean ok) throws IOException {
                    try {
                        os.close();
                    } catch (IOException e) {
                        // ignore
                    }
                    if (ok) {
                        ContentValues u = new ContentValues();
                        u.put(MediaStore.MediaColumns.IS_PENDING, 0);
                        cr.update(uri, u, null, null);
                    } else {
                        cr.delete(uri, null, null);
                    }
                    return "Downloads/AirLink";
                }
            };
        }
        File base = ctx.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
        if (base == null) base = ctx.getFilesDir();
        File dir = new File(base, "AirLink");
        dir.mkdirs();
        File f = new File(dir, name);
        int n = 1;
        int dot = name.lastIndexOf('.');
        String stem = dot > 0 ? name.substring(0, dot) : name;
        String ext = dot > 0 ? name.substring(dot) : "";
        while (f.exists()) f = new File(dir, stem + " (" + (n++) + ")" + ext);
        final File target = f;
        final OutputStream os = new FileOutputStream(target);
        return new LanServer.Upload() {
            public OutputStream stream() {
                return os;
            }

            public String finish(boolean ok) throws IOException {
                try {
                    os.close();
                } catch (IOException e) {
                    // ignore
                }
                if (!ok) target.delete();
                return target.getParent();
            }
        };
    }
}
