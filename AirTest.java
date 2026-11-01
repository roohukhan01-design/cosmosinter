package com.roohu.airlink;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.zip.*;

public class AirTest {
  static int pass=0, fail=0;
  static void ok(boolean c, String m){ if(c){pass++;System.out.println("  ok   "+m);} else {fail++;System.out.println("  FAIL "+m);} }

  static class H implements LanServer.Host {
    final List<LanServer.Item> items = new CopyOnWriteArrayList<>();
    final Map<String,byte[]> data = new ConcurrentHashMap<>();
    final Map<String,byte[]> got = new ConcurrentHashMap<>();
    final Map<String,String> gotSha = new ConcurrentHashMap<>();
    volatile boolean allow = true; final AtomicInteger approvals=new AtomicInteger();
    final AtomicInteger sessionsChanged=new AtomicInteger(), clipsSeen=new AtomicInteger();
    volatile boolean idle=false;
    public List<LanServer.Item> shared(){ return new ArrayList<>(items); }
    public InputStream open(LanServer.Item it){ return new ByteArrayInputStream(data.get(it.id)); }
    public LanServer.Upload createUpload(String name,long len){
      final ByteArrayOutputStream bo=new ByteArrayOutputStream();
      return new LanServer.Upload(){ public OutputStream stream(){return bo;} public String finish(boolean ok){ if(ok) got.put(name,bo.toByteArray()); return "Mem"; } };
    }
    public InputStream page(){ return new ByteArrayInputStream("<html>hi</html>".getBytes()); }
    public String deviceName(){ return "TestPhone"; }
    public long freeSpace(){ return 50L<<20; }
    public void onProgress(String n,long d,long t,boolean u){}
    public void onReceived(String n,long s,String w,String sha){ gotSha.put(n,sha); }
    public boolean approve(String n,String ip,String id){ approvals.incrementAndGet(); try{Thread.sleep(150);}catch(Exception e){} return allow; }
    public void onSessions(){ sessionsChanged.incrementAndGet(); }
    public void onClip(LanServer.Clip c){ clipsSeen.incrementAndGet(); }
    public void onIdleStop(){ idle=true; }
    LanServer.Item add(String name, byte[] b){ LanServer.Item it=new LanServer.Item(); it.id=String.valueOf(items.size()+1); it.name=name; it.size=b.length; items.add(it); data.put(it.id,b); return it; }
  }
  static byte[] rnd(int n,long seed){ byte[] b=new byte[n]; new Random(seed).nextBytes(b); return b; }
  static String sha(byte[] b){ MessageDigest m=LanServer.sha256(); return LanServer.hex(m.digest(b)); }

  static class Slow extends FilterInputStream { // throws once at a position
    long pos=0, failAt; boolean thrown=false; final long delay;
    Slow(InputStream in,long failAt,long delay){super(in);this.failAt=failAt;this.delay=delay;}
    public int read(byte[] b,int o,int l) throws IOException{
      if(failAt>=0 && !thrown && pos>=failAt){thrown=true; throw new IOException("simulated wifi drop");}
      if(delay>0) try{Thread.sleep(delay);}catch(Exception e){}
      int n=in.read(b,o,(int)Math.min(l, failAt>=0&&!thrown? Math.max(1,failAt-pos):l)); if(n>0)pos+=n; return n; }
  }

  public static void main(String[] a) throws Exception {
    System.out.println("security primitives");
    AirLinkSecurity.PairingCode pc = new AirLinkSecurity.PairingCode();
    pc.issue("654321", 1000L, 5000L);
    ok(!pc.matches("654321", 6000L), "pairing code expires at its deadline");
    pc.issue("654321", 1000L, 5000L);
    ok(pc.consume("654321", 1001L), "valid pairing code consumed once");
    ok(!pc.consume("654321", 1002L), "pairing code cannot be reused");
    AirLinkSecurity.AttemptLimiter limiter = new AirLinkSecurity.AttemptLimiter(3, 2, 1000L);
    ok(limiter.allow("10.0.0.1", 1000L), "limiter initially allows IP");
    limiter.failure("10.0.0.1", 1000L); limiter.failure("10.0.0.1", 1001L);
    ok(!limiter.allow("10.0.0.1", 1002L), "per-IP backoff activates");
    limiter.failure("10.0.0.2", 1003L);
    ok(!limiter.allow("10.0.0.3", 1004L), "global authentication budget applies across IPs");
    ok(limiter.trackedIps() <= 256, "IP tracking is bounded");
    AirLinkSecurity.TlsEndpoint certA = AirLinkSecurity.createTlsEndpoint(0);
    AirLinkSecurity.TlsEndpoint certB = AirLinkSecurity.createTlsEndpoint(0);
    ok(!certA.fingerprint.equals(certB.fingerprint), "TLS identity rotates between sessions");
    certA.socket.close(); certB.socket.close();
    ok("report_final.txt".equals(AirLinkSecurity.validateFilename("report:final.txt")), "filename sanitizer replaces unsafe characters");
    try { AirLinkSecurity.validateFilename("..\\escape.txt"); ok(false, "path traversal rejected"); } catch (IllegalArgumentException e) { ok(true, "path traversal rejected"); }
    try { AirLinkSecurity.validateUpload(0, 0, AirLinkSecurity.MAX_UPLOAD_BYTES + 1, AirLinkSecurity.MAX_UPLOAD_BYTES); ok(false, "oversized upload rejected"); } catch (IllegalArgumentException e) { ok(true, "oversized upload rejected"); }
    try { AirLinkSecurity.validateUpload(Long.MAX_VALUE - 2, 10, Long.MAX_VALUE, AirLinkSecurity.MAX_UPLOAD_BYTES); ok(false, "overflow-safe offset validation"); } catch (IllegalArgumentException e) { ok(true, "overflow-safe offset validation"); }

    H h=new H(); LanServer s=new LanServer(h);
    int port=s.start(0,"123456",true,0);
    String host="127.0.0.1";
    ok(s.tlsPort() > 0 && s.tlsFingerprint().matches("[0-9A-F]{64}"), "session TLS listener and SHA-256 fingerprint created");
    byte[] big=rnd(10*1024*1024+123,1), small="hello world".getBytes(), empty=new byte[0];
    h.add("big.bin",big); h.add("small.txt",small); h.add("empty.dat",empty); h.add("small.txt",small);

    System.out.println("auth");
    try{ LanClient.auth(host,port,"000000","clientAAAA","PC"); ok(false,"wrong code rejected"); }catch(LanClient.HttpError e){ ok(e.status==403,"wrong code -> 403"); }
    h.allow=false;
    try{ LanClient.auth(host,port,"123456","clientAAAA","PC"); ok(false,"denied"); }catch(LanClient.HttpError e){ ok(e.status==403&&e.code.equals("denied"),"owner denies -> denied"); }
    h.allow=true;
    LanClient.pinTls(host, s.tlsPort(), "00".repeat(32));
    try { LanClient.auth(host,s.tlsPort(),"123456","tlsMismatch","Wrong Pin"); ok(false,"wrong TLS fingerprint rejected"); }
    catch(IOException e) { ok(e.getMessage().contains("Secure AirLink"),"wrong TLS fingerprint rejected before credentials"); }
    LanClient.pinTls(host, s.tlsPort(), s.tlsFingerprint());
    String tok=LanClient.auth(host,s.tlsPort(),"123456","clientAAAA","My PC");
    ok(tok.length()==32,"pinned TLS authentication succeeds");
    try { LanClient.auth(host,s.tlsPort(),"123456","clientBBBB","Second PC"); ok(false,"pairing code is one-time across devices"); }
    catch(LanClient.HttpError e) { ok(e.status==403&&"code".equals(e.code),"pairing code is one-time across devices"); }
    ok(s.trustedDevices().size()==1,"trusted device is recorded");
    LanServer restoredTrust = new LanServer(h, s.exportTrustedSecrets());
    restoredTrust.start(0, "654321", true, 0);
    ok(restoredTrust.trustedDevices().size()==1,"trusted device credentials restore across server sessions");
    LanClient.pinTls(host, restoredTrust.tlsPort(), restoredTrust.tlsFingerprint());
    String restoredToken = LanClient.auth(host, restoredTrust.tlsPort(), "000000", "clientAAAA", "My PC");
    ok(restoredToken.length()==32,"trusted device reconnects after TLS certificate and port rotate");
    restoredTrust.stop();
    ok(tok.length()==32,"token issued (128-bit)");
    int ap=h.approvals.get();
    String tok2=LanClient.auth(host,s.tlsPort(),"123456","clientAAAA","My PC");
    ok(h.approvals.get()==ap,"trusted device not asked again");
    try{ LanClient.getText(host,port,tok,"/api/list"); ok(false,"old token dead"); }catch(LanClient.HttpError e){ ok(e.isAuth(),"re-auth replaces old token"); }
    tok=tok2;
    final String T=tok;
    try{ LanClient.getText(host,port,"nope","/api/list"); ok(false,"bad token"); }catch(LanClient.HttpError e){ ok(e.status==401,"bad token -> 401"); }
    String ping=LanClient.getText(host,port,tok,"/api/ping");
    ok(ping.contains("TestPhone")&&ping.contains("\"v\":2"),"ping");
    String list=LanClient.getText(host,port,tok,"/api/list");
    ok(list.contains("big.bin")&&list.contains("empty.dat"),"list files");

    System.out.println("download + resume + verify");
    ByteArrayOutputStream bo=new ByteArrayOutputStream();
    final ByteArrayOutputStream bo0=bo;
    LanClient.DownloadState st=new LanClient.DownloadState();
    final long cut=3_000_000;
    OutputStream flaky=new OutputStream(){ public void write(int b){bo0.write(b);} public void write(byte[] b,int o,int l) throws IOException{ if(bo0.size()>=cut) throw new IOException("drop"); bo0.write(b,o,l);} };
    try{ LanClient.download(host,port,tok,"1",flaky,st,null,null); ok(false,"should drop"); }catch(IOException e){ ok(st.done>=cut,"download dropped at "+st.done); }
    LanClient.download(host,port,tok,"1",bo,st,null,null);
    ok(Arrays.equals(bo.toByteArray(),big),"resumed download is byte-identical");
    ok(LanServer.hex(st.md.digest()).equals(LanClient.remoteHash(host,port,tok,"1")),"sha256 matches remote hash");
    ok(sha(big).equals(LanClient.remoteHash(host,port,tok,"1")),"remote hash correct");
    bo=new ByteArrayOutputStream(); st=new LanClient.DownloadState();
    LanClient.download(host,port,tok,"3",bo,st,null,null); ok(bo.size()==0&&st.total==0,"empty file downloads");
    // raw range
    Socket sk=new Socket(host,port); sk.getOutputStream().write(("GET /f/2 HTTP/1.1\r\nX-Token: "+tok+"\r\nRange: bytes=6-\r\nConnection: close\r\n\r\n").getBytes());
    String resp=new String(sk.getInputStream().readAllBytes()); sk.close();
    ok(resp.startsWith("HTTP/1.1 206")&&resp.endsWith("world")&&resp.contains("Content-Range: bytes 6-10/11"),"Range 206 + Content-Range");
    sk=new Socket(host,port); sk.getOutputStream().write(("GET /f/2 HTTP/1.1\r\nX-Token: "+tok+"\r\nRange: bytes=99-\r\nConnection: close\r\n\r\n").getBytes());
    resp=new String(sk.getInputStream().readAllBytes()); sk.close();
    ok(resp.startsWith("HTTP/1.1 416"),"bad range -> 416");

    System.out.println("upload chunked + verify");
    final byte[] up=rnd(10*1024*1024+7,2);
    String r=LanClient.upload(host,port,tok,"up.bin",()->new ByteArrayInputStream(up),up.length,"uploadid0001",null,null);
    ok(Arrays.equals(h.got.get("up.bin"),up),"10 MB chunked upload identical");
    ok(r.equals(sha(up))&&sha(up).equals(h.gotSha.get("up.bin")),"upload sha256 verified both sides");
    LanClient.upload(host,port,tok,"zero.dat",()->new ByteArrayInputStream(new byte[0]),0,"uploadid0002",null,null);
    ok(h.got.containsKey("zero.dat")&&h.got.get("zero.dat").length==0,"empty upload completes");
    try { LanClient.postText(host,port,tok,"/upload","","X-Filename: ..%2Fescape.txt\r\nX-Upload-Id: traver001\r\nX-Offset: 0\r\nX-Total: 0\r\n"); ok(false,"upload route rejects traversal filename"); }
    catch(LanClient.HttpError e) { ok(e.status==400&&"filename".equals(e.code),"upload route rejects traversal filename"); }
    try { LanClient.postText(host,port,tok,"/upload","","X-Filename: huge.bin\r\nX-Upload-Id: hugefile001\r\nX-Offset: 0\r\nX-Total: 21474836481\r\n"); ok(false,"upload route rejects over-limit file"); }
    catch(LanClient.HttpError e) { ok(e.status==413&&"size".equals(e.code),"upload route rejects over-limit file"); }

    System.out.println("upload resume after real connection drop");
    final int realPort=port; final AtomicBoolean killOnce=new AtomicBoolean(true);
    final ServerSocket px=new ServerSocket(0);
    Thread pt=new Thread(()->{ try{ while(true){ final Socket c=px.accept(); new Thread(()->{ try{ final Socket u=new Socket("127.0.0.1",realPort);
      Thread d=new Thread(()->{ try{ InputStream i=u.getInputStream(); OutputStream o=c.getOutputStream(); byte[] bf=new byte[65536]; int n; while((n=i.read(bf))>0){o.write(bf,0,n);o.flush();} }catch(Exception e){} try{c.close();}catch(Exception e){} }); d.start();
      InputStream i=c.getInputStream(); OutputStream o=u.getOutputStream(); byte[] bf=new byte[65536]; int n; long fwd=0; boolean isUp=false; boolean first=true;
      while((n=i.read(bf))>0){ if(first){ isUp=new String(bf,0,Math.min(n,12)).startsWith("POST /upload"); first=false; }
        if(isUp&&fwd>1_500_000&&killOnce.compareAndSet(true,false)){ c.setSoLinger(true,0); c.close(); u.close(); return; }
        o.write(bf,0,n);o.flush();fwd+=n; }
      u.shutdownOutput(); }catch(Exception e){} }).start(); } }catch(Exception e){} });
    pt.setDaemon(true); pt.start();
    final byte[] up2=rnd(12*1024*1024+5,3);
    final AtomicInteger opens=new AtomicInteger();
    String r2=LanClient.upload(host,px.getLocalPort(),tok,"resume.bin",()->{ opens.incrementAndGet(); return new ByteArrayInputStream(up2); },up2.length,"uploadid0003",null,null);
    ok(!killOnce.get(),"connection was really cut mid-chunk");
    ok(opens.get()>=2,"source reopened + hash rebuilt after drop ("+opens.get()+" opens)");
    ok(Arrays.equals(h.got.get("resume.bin"),up2)&&r2.equals(sha(up2)),"resumed upload identical + hash ok");
    px.close();

    System.out.println("integrity failure + legacy upload");
    LanClient.postText(host,port,tok,"/upload","abcdefghij","X-Filename: bad.txt\r\nX-Upload-Id: uploadid0004\r\nX-Offset: 0\r\nX-Total: 10\r\n");
    try{ LanClient.postText(host,port,tok,"/api/upload-finish","","X-Upload-Id: uploadid0004\r\nX-Sha256: deadbeef\r\n"); ok(false,"hash mismatch"); }catch(LanClient.HttpError e){ ok(e.status==422&&e.code.equals("hash"),"wrong checksum -> 422"); }
    ok(!h.got.containsKey("bad.txt"),"damaged file discarded");
    LanClient.postText(host,port,tok,"/upload","legacy!","X-Filename: legacy.txt\r\n");
    ok(new String(h.got.get("legacy.txt")).equals("legacy!"),"legacy single-shot upload still works");
    try{ LanClient.postText(host,port,tok,"/upload","x","X-Filename: o.txt\r\nX-Upload-Id: uploadid0005\r\nX-Offset: 5\r\nX-Total: 10\r\n"); ok(false,"restart"); }catch(LanClient.HttpError e){ ok(e.status==409&&e.code.equals("restart"),"unknown partial -> restart"); }

    System.out.println("zip");
    sk=new Socket(host,port); sk.getOutputStream().write(("GET /zip HTTP/1.1\r\nX-Token: "+tok+"\r\nConnection: close\r\n\r\n").getBytes());
    byte[] all=sk.getInputStream().readAllBytes(); sk.close();
    int idx=new String(all,StandardCharsets.ISO_8859_1).indexOf("\r\n\r\n")+4;
    ZipInputStream zi=new ZipInputStream(new ByteArrayInputStream(all,idx,all.length-idx)); List<String> names=new ArrayList<>(); ZipEntry ze; long bigLen=0;
    while((ze=zi.getNextEntry())!=null){ names.add(ze.getName()); byte[] d=zi.readAllBytes(); if(ze.getName().equals("big.bin")) bigLen=d.length; }
    ok(names.equals(Arrays.asList("big.bin","small.txt","empty.dat","small (1).txt")),"zip entries "+names);
    ok(bigLen==big.length,"zip content intact");

    System.out.println("clipboard");
    LanClient.postText(host,port,tok,"/api/clip","hello from pc \u00e9\u4e2d","X-From: My%20PC\r\n");
    String cl=LanClient.getText(host,port,tok,"/api/clips");
    ok(cl.contains("hello from pc")&&cl.contains("My PC")&&h.clipsSeen.get()==1,"clip stored + host notified");
    s.addClip("This phone","from phone"); ok(LanClient.getText(host,port,tok,"/api/clips").contains("from phone"),"phone clip visible to PC");

    System.out.println("cancel");
    final byte[] up3=rnd(9*1024*1024,4); final AtomicReference<Throwable> err=new AtomicReference<>();
    Thread th=new Thread(()->{ try{ LanClient.upload(host,port,T,"cancelme.bin",()->new Slow(new ByteArrayInputStream(up3),-1,25),up3.length,"uploadid0006",null,null);}catch(Throwable e){err.set(e);} });
    th.start(); Thread.sleep(700); s.cancel("cancelme.bin"); th.join(20000);
    ok(err.get()!=null&&!h.got.containsKey("cancelme.bin"),"phone cancels incoming upload: "+err.get());

    System.out.println("parallel uploads");
    ExecutorService ex=Executors.newFixedThreadPool(6); List<Future<Boolean>> fs=new ArrayList<>();
    for(int i=0;i<6;i++){ final int k=i; fs.add(ex.submit(()->{ byte[] d=rnd(2_000_000+k,100+k); LanClient.upload(host,port,T,"p"+k+".bin",()->new ByteArrayInputStream(d),d.length,"parallelid"+k+"xx",null,null); return Arrays.equals(h.got.get("p"+k+".bin"),d); })); }
    boolean allok=true; for(Future<Boolean> f:fs) allok&=f.get(); ok(allok,"6 parallel uploads all correct");
    ex.shutdown();

    System.out.println("sessions");
    List<LanServer.Session> ss=s.sessions(); ok(ss.size()==1&&ss.get(0).name.equals("My PC"),"device listed: "+ss.get(0).name);
    s.revoke(ss.get(0).id);
    ok(s.trustedDevices().isEmpty(),"revocation removes trusted-device record and secret");
    try{ LanClient.getText(host,port,tok,"/api/list"); ok(false,"revoked"); }catch(LanClient.HttpError e){ ok(e.isAuth(),"revoked device is logged out"); }
    s.setKey("999999");
    try{ LanClient.getText(host,port,tok,"/api/list"); ok(false,"rotate"); }catch(LanClient.HttpError e){ ok(e.isAuth(),"rotated code invalidates old sessions"); }
    String t3=LanClient.auth(host,s.tlsPort(),"999999","clientAAAA","My PC");
    ok(h.approvals.get()>ap,"revoked device must be approved again with a new code");
    ok(LanClient.getText(host,port,t3,"/api/list").contains("big.bin"),"new code establishes a fresh trusted session");

    System.out.println("brute force lock");
    int code=0; for(int i=0;i<8;i++){ try{ LanClient.auth(host,port,"111111","bruteforce1","X"); }catch(LanClient.HttpError e){ code=e.status; } }
    ok(code==429,"locked after repeated wrong codes (429)");
    try{ LanClient.auth(host,port,"999999","bruteforce1","X"); ok(false,"locked even with right code"); }catch(LanClient.HttpError e){ ok(e.status==429,"right code refused while locked"); }

    System.out.println("page + idle stop");
    sk=new Socket(host,port); sk.getOutputStream().write("GET / HTTP/1.1\r\nConnection: close\r\n\r\n".getBytes()); resp=new String(sk.getInputStream().readAllBytes()); sk.close();
    ok(resp.contains("<html>hi</html>"),"PC page served without login");
    java.lang.reflect.Field f=LanServer.class.getDeclaredField("idleMs"); f.setAccessible(true); f.set(s,1000L);
    java.lang.reflect.Field la=LanServer.class.getDeclaredField("lastActivity"); la.setAccessible(true); la.set(s,System.currentTimeMillis()-5000);
    Thread.sleep(6500); ok(h.idle,"idle auto-off fires");
    s.stop();
    System.out.println("\n"+pass+" passed, "+fail+" failed");
    System.exit(fail==0?0:1);
  }
}
