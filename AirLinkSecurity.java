package com.roohu.airlink;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import java.security.KeyStore;

/** Security primitives shared by AirLink's pure-Java server and test harness. */
public final class AirLinkSecurity {
    public static final long DEFAULT_PAIRING_TTL_MS = 5L * 60L * 1000L;
    public static final long MAX_UPLOAD_BYTES = 20L * 1024L * 1024L * 1024L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private AirLinkSecurity() {}

    public static final class PairingCode {
        private String value;
        private long expiresAt;
        private boolean consumed;
        public synchronized void issue(String code, long now, long ttlMs) {
            if (code == null || !code.matches("[0-9]{6}")) throw new IllegalArgumentException("Pairing code must be six digits");
            value = code; expiresAt = now + Math.max(1L, ttlMs); consumed = false;
        }
        public synchronized boolean matches(String candidate, long now) {
            if (consumed || value == null || now >= expiresAt || candidate == null) return false;
            return MessageDigest.isEqual(value.getBytes(java.nio.charset.StandardCharsets.US_ASCII), candidate.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
        public synchronized boolean consume(String candidate, long now) {
            if (!matches(candidate, now)) return false;
            consumed = true; return true;
        }
        public synchronized boolean isExpired(long now) { return value == null || consumed || now >= expiresAt; }
        public synchronized long expiresAt() { return expiresAt; }
        public synchronized void clear() { value = null; expiresAt = 0; consumed = true; }
    }

    /** Bounded per-IP exponential backoff plus a global rolling-minute budget. */
    public static final class AttemptLimiter {
        private static final class Entry { int failures; long lockedUntil; long touched; }
        private final Map<String, Entry> ips = new ConcurrentHashMap<String, Entry>();
        private final long[] global = new long[30];
        private int cursor;
        private int count;
        private final int globalLimit;
        private final int ipLimit;
        private final long baseBackoffMs;
        public AttemptLimiter() { this(30, 5, 30_000L); }
        public AttemptLimiter(int globalLimit, int ipLimit, long baseBackoffMs) {
            this.globalLimit = globalLimit; this.ipLimit = ipLimit; this.baseBackoffMs = baseBackoffMs;
        }
        public synchronized boolean allow(String ip, long now) {
            pruneGlobal(now);
            if (count >= globalLimit) return false;
            Entry e = ips.get(ip);
            return e == null || e.lockedUntil <= now;
        }
        public synchronized void failure(String ip, long now) {
            pruneGlobal(now);
            if (count < global.length) count++;
            global[cursor] = now; cursor = (cursor + 1) % global.length;
            Entry e = ips.get(ip);
            if (e == null) {
                if (ips.size() >= 256) evictOldest();
                e = new Entry(); ips.put(ip, e);
            }
            e.failures++; e.touched = now;
            if (e.failures >= ipLimit) {
                int shift = Math.min(6, e.failures - ipLimit);
                long backoff = Math.min(30L * 60L * 1000L, baseBackoffMs << shift);
                e.lockedUntil = now + backoff;
            }
        }
        public synchronized void success(String ip) { ips.remove(ip); }
        public synchronized int trackedIps() { return ips.size(); }
        private void pruneGlobal(long now) {
            int kept = 0;
            for (int i = 0; i < global.length; i++) if (global[i] > 0 && now - global[i] < 60_000L) kept++;
            count = kept;
            if (count == 0) { Arrays.fill(global, 0L); cursor = 0; }
        }
        private void evictOldest() {
            String oldestKey = null; long oldest = Long.MAX_VALUE;
            for (Map.Entry<String, Entry> x : ips.entrySet()) if (x.getValue().touched < oldest) { oldest=x.getValue().touched; oldestKey=x.getKey(); }
            if (oldestKey != null) ips.remove(oldestKey);
        }
    }

    public static String validateFilename(String raw) {
        if (raw == null || raw.length() == 0 || raw.length() > 255) throw new IllegalArgumentException("Invalid filename");
        if (raw.indexOf('/') >= 0 || raw.indexOf('\\') >= 0 || raw.equals(".") || raw.equals("..")) throw new IllegalArgumentException("Path traversal is not allowed");
        StringBuilder b = new StringBuilder();
        for (int i=0;i<raw.length();i++) {
            char c=raw.charAt(i);
            if (c < 32 || c == 127 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') b.append('_');
            else b.append(c);
        }
        String out=b.toString().trim();
        while (out.startsWith(".")) out=out.substring(1);
        if (out.isEmpty()) throw new IllegalArgumentException("Invalid filename");
        if (out.length()>150) out=out.substring(out.length()-150);
        return out;
    }

    public static void validateUpload(long offset, long chunkLength, long total, long maxBytes) {
        if (offset < 0 || chunkLength < 0 || total < 0 || total > maxBytes || offset > total || chunkLength > total - offset)
            throw new IllegalArgumentException("Invalid upload size or offset");
    }

    /** A fresh P-256 self-signed certificate and TLS listener for one sharing session. */
    public static final class TlsEndpoint {
        public final SSLServerSocket socket;
        public final String fingerprint;
        private TlsEndpoint(SSLServerSocket socket, String fingerprint) { this.socket=socket; this.fingerprint=fingerprint; }
    }

    public static TlsEndpoint createTlsEndpoint(int port) throws Exception {
        KeyPairGenerator gen=KeyPairGenerator.getInstance("EC");
        gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), RANDOM);
        KeyPair kp=gen.generateKeyPair();
        X509Certificate cert=createCertificate(kp);
        cert.checkValidity(); cert.verify(kp.getPublic());
        String fp=hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        KeyStore ks=KeyStore.getInstance(KeyStore.getDefaultType()); ks.load(null, null);
        ks.setKeyEntry("airlink-session", kp.getPrivate(), new char[0], new java.security.cert.Certificate[]{cert});
        KeyManagerFactory kmf=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); kmf.init(ks, new char[0]);
        SSLContext ctx=SSLContext.getInstance("TLS"); ctx.init(kmf.getKeyManagers(), null, RANDOM);
        SSLServerSocket ss=(SSLServerSocket)ctx.getServerSocketFactory().createServerSocket();
        ss.setReuseAddress(true); ss.bind(new InetSocketAddress(port));
        java.util.List<String> enabled = new java.util.ArrayList<String>();
        for (String protocol : ss.getSupportedProtocols()) if ("TLSv1.3".equals(protocol) || "TLSv1.2".equals(protocol)) enabled.add(protocol);
        if (enabled.isEmpty()) throw new IOException("TLS 1.2 or newer is required");
        ss.setEnabledProtocols(enabled.toArray(new String[enabled.size()]));
        return new TlsEndpoint(ss, fp);
    }

    private static X509Certificate createCertificate(KeyPair kp) throws Exception {
        byte[] alg=seq(oid(1,2,840,10045,4,3,2)); // ecdsa-with-SHA256
        byte[] name=seq(set(seq(oid(2,5,4,3), utf8("AirLink Session"))));
        long now=System.currentTimeMillis();
        byte[] validity=seq(utc(now-60_000L), utc(now+24L*60L*60L*1000L));
        byte[] serial=integer(new BigInteger(159, RANDOM).add(BigInteger.ONE));
        byte[] tbs=seq(context0(integer(BigInteger.valueOf(2))), serial, alg, name, validity, name, kp.getPublic().getEncoded());
        Signature sig=Signature.getInstance("SHA256withECDSA"); sig.initSign(kp.getPrivate(), RANDOM); sig.update(tbs);
        byte[] cert=seq(tbs, alg, bitString(sig.sign()));
        return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert));
    }
    private static String hex(byte[] b) { StringBuilder s=new StringBuilder(); for(byte x:b)s.append(String.format(java.util.Locale.ROOT,"%02X",x&255)); return s.toString(); }
    private static byte[] tlv(int tag, byte[] body) throws IOException { ByteArrayOutputStream o=new ByteArrayOutputStream();o.write(tag);writeLen(o,body.length);o.write(body);return o.toByteArray(); }
    private static void writeLen(ByteArrayOutputStream o,int n){if(n<128)o.write(n);else{int k=0,v=n;while(v>0){k++;v>>=8;}o.write(0x80|k);for(int i=k-1;i>=0;i--)o.write((n>>(8*i))&255);}}
    private static byte[] join(byte[]... a)throws IOException{ByteArrayOutputStream o=new ByteArrayOutputStream();for(byte[] b:a)o.write(b);return o.toByteArray();}
    private static byte[] seq(byte[]... a)throws IOException{return tlv(0x30,join(a));}
    private static byte[] set(byte[]... a)throws IOException{return tlv(0x31,join(a));}
    private static byte[] integer(BigInteger n)throws IOException{return tlv(0x02,n.toByteArray());}
    private static byte[] utf8(String s)throws IOException{return tlv(0x0c,s.getBytes("UTF-8"));}
    private static byte[] bitString(byte[] b)throws IOException{return tlv(0x03,join(new byte[]{0},b));}
    private static byte[] context0(byte[] b)throws IOException{return tlv(0xa0,b);}
    private static byte[] utc(long ms)throws IOException{java.text.SimpleDateFormat f=new java.text.SimpleDateFormat("yyMMddHHmmss'Z'",java.util.Locale.US);f.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));return tlv(0x17,f.format(new java.util.Date(ms)).getBytes("US-ASCII"));}
    private static byte[] oid(int... ids)throws IOException{ByteArrayOutputStream o=new ByteArrayOutputStream();o.write(ids[0]*40+ids[1]);for(int i=2;i<ids.length;i++){long v=ids[i];byte[] t=new byte[10];int p=9;t[p]=(byte)(v&127);while((v>>=7)>0)t[--p]=(byte)(0x80|(v&127));o.write(t,p,10-p);}return tlv(0x06,o.toByteArray());}
}
