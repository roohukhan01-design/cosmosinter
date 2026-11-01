import { store } from './core/storage.js';
import { getLanSharePlugin } from './api/native.js';
import { applyTheme } from './theme.js';
import { t } from './i18n/strings.js';
import { createState } from './core/state.js';
import { createViews } from './views/main.js';


/* Minimal offline QR encoder (byte mode, error level M, versions 1-10). */
function qrMatrix(text){
  var data=[];var s=unescape(encodeURIComponent(text));for(var i=0;i<s.length;i++)data.push(s.charCodeAt(i));
  var ECC=[0,10,16,26,18,24,16,18,22,22,26],BLK=[0,1,1,1,2,2,4,4,4,5,5];
  function raw(v){var r=(16*v+128)*v+64;if(v>=2){var n=Math.floor(v/7)+2;r-=(25*n-10)*n-55;if(v>=7)r-=36}return r}
  var ver,cap=0;
  for(ver=1;ver<=10;ver++){cap=Math.floor(raw(ver)/8)-ECC[ver]*BLK[ver];if(4+(ver<10?8:16)+data.length*8<=cap*8)break}
  if(ver>10)return null;
  var bits=[];function put(v,n){for(var i=n-1;i>=0;i--)bits.push((v>>>i)&1)}
  put(4,4);put(data.length,ver<10?8:16);data.forEach(function(b){put(b,8)});
  put(0,Math.min(4,cap*8-bits.length));while(bits.length%8)bits.push(0);
  for(var pad=0xEC;bits.length<cap*8;pad^=0xEC^0x11)put(pad,8);
  var cw=[];for(i=0;i<bits.length;i+=8){var b=0;for(var k=0;k<8;k++)b=(b<<1)|bits[i+k];cw.push(b)}
  function mul(x,y){var z=0;for(var i=7;i>=0;i--){z=(z<<1)^((z>>>7)*0x11D);z^=((y>>>i)&1)*x}return z}
  function divisor(d){var r=[];for(var i=0;i<d;i++)r.push(0);r[d-1]=1;var root=1;for(i=0;i<d;i++){for(var j=0;j<r.length;j++){r[j]=mul(r[j],root);if(j+1<r.length)r[j]^=r[j+1]}root=mul(root,2)}return r}
  function rem(dat,div){var r=div.map(function(){return 0});dat.forEach(function(b){var f=b^r.shift();r.push(0);div.forEach(function(c,i){r[i]^=mul(c,f)})});return r}
  var nb=BLK[ver],el=ECC[ver],rc=Math.floor(raw(ver)/8),ns=nb-rc%nb,sl=Math.floor(rc/nb),div=divisor(el),blocks=[],p=0;
  for(i=0;i<nb;i++){var dl=sl-el+(i<ns?0:1),dat=cw.slice(p,p+dl);p+=dl;var ecc=rem(dat,div);if(i<ns)dat.push(0);blocks.push(dat.concat(ecc))}
  var all=[];for(i=0;i<blocks[0].length;i++)for(var j=0;j<nb;j++)if(i!=sl-el||j>=ns)all.push(blocks[j][i]);
  var n=ver*4+17,M=[],F=[];for(i=0;i<n;i++){M.push(new Array(n).fill(false));F.push(new Array(n).fill(false))}
  function sf(x,y,d){M[y][x]=d;F[y][x]=true}
  for(i=0;i<n;i++){sf(6,i,i%2==0);sf(i,6,i%2==0)}
  function finder(x,y){for(var dy=-4;dy<=4;dy++)for(var dx=-4;dx<=4;dx++){var d=Math.max(Math.abs(dx),Math.abs(dy)),xx=x+dx,yy=y+dy;if(xx>=0&&xx<n&&yy>=0&&yy<n)sf(xx,yy,d!=2&&d!=4)}}
  finder(3,3);finder(n-4,3);finder(3,n-4);
  var al=[];if(ver>1){var na=Math.floor(ver/7)+2,step=Math.ceil((ver*4+4)/(na*2-2))*2;al=[6];for(var pos=n-7;al.length<na;pos-=step)al.splice(1,0,pos)}
  for(i=0;i<al.length;i++)for(j=0;j<al.length;j++){if((i==0&&j==0)||(i==0&&j==al.length-1)||(i==al.length-1&&j==0))continue;for(var dy=-2;dy<=2;dy++)for(var dx=-2;dx<=2;dx++)sf(al[i]+dx,al[j]+dy,Math.max(Math.abs(dx),Math.abs(dy))!=1)}
  function bit(x,i){return((x>>>i)&1)!=0}
  function fmt(mask){var d=mask,r=d;for(var i=0;i<10;i++)r=(r<<1)^((r>>>9)*0x537);var b=((d<<10)|r)^0x5412;
    for(i=0;i<=5;i++)sf(8,i,bit(b,i));sf(8,7,bit(b,6));sf(8,8,bit(b,7));sf(7,8,bit(b,8));for(i=9;i<15;i++)sf(14-i,8,bit(b,i));
    for(i=0;i<8;i++)sf(n-1-i,8,bit(b,i));for(i=8;i<15;i++)sf(8,n-15+i,bit(b,i));sf(8,n-8,true)}
  fmt(0);
  if(ver>=7){var r2=ver;for(i=0;i<12;i++)r2=(r2<<1)^((r2>>>11)*0x1F25);var vb=(ver<<12)|r2;for(i=0;i<18;i++){var bt=bit(vb,i),a=n-11+i%3,b2=Math.floor(i/3);sf(a,b2,bt);sf(b2,a,bt)}}
  var q=0;for(var right=n-1;right>=1;right-=2){if(right==6)right=5;for(var vert=0;vert<n;vert++)for(j=0;j<2;j++){var x=right-j,up=((right+1)&2)==0,y=up?n-1-vert:vert;if(!F[y][x]&&q<all.length*8){M[y][x]=bit(all[q>>>3],7-(q&7));q++}}}
  function mask(m){for(var y=0;y<n;y++)for(var x=0;x<n;x++){var inv;switch(m){case 0:inv=(x+y)%2==0;break;case 1:inv=y%2==0;break;case 2:inv=x%3==0;break;case 3:inv=(x+y)%3==0;break;case 4:inv=(Math.floor(x/3)+Math.floor(y/2))%2==0;break;case 5:inv=x*y%2+x*y%3==0;break;case 6:inv=(x*y%2+x*y%3)%2==0;break;default:inv=((x+y)%2+x*y%3)%2==0}if(!F[y][x]&&inv)M[y][x]=!M[y][x]}}
  function pen(){var s=0,y,x,run,c;for(y=0;y<n;y++){run=1;for(x=1;x<n;x++){if(M[y][x]==M[y][x-1]){run++;if(run==5)s+=3;else if(run>5)s++}else run=1}}
    for(x=0;x<n;x++){run=1;for(y=1;y<n;y++){if(M[y][x]==M[y-1][x]){run++;if(run==5)s+=3;else if(run>5)s++}else run=1}}
    for(y=0;y<n-1;y++)for(x=0;x<n-1;x++){c=M[y][x];if(c==M[y][x+1]&&c==M[y+1][x]&&c==M[y+1][x+1])s+=3}
    var dark=0;for(y=0;y<n;y++)for(x=0;x<n;x++)if(M[y][x])dark++;s+=Math.floor(Math.abs(dark*20-n*n*10)/(n*n))*10;return s}
  var best=0,bp=1e9;for(var m=0;m<8;m++){mask(m);fmt(m);var pp=pen();if(pp<bp){bp=pp;best=m}mask(m)}
  mask(best);fmt(best);return M;
}
function qrSvg(text,px){var M=qrMatrix(text);if(!M)return'';var n=M.length,q=4,d='';for(var y=0;y<n;y++)for(var x=0;x<n;x++)if(M[y][x])d+='M'+(x+q)+' '+(y+q)+'h1v1h-1z';
  return'<svg viewBox="0 0 '+(n+2*q)+' '+(n+2*q)+'" width="'+px+'" height="'+px+'" shape-rendering="crispEdges" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" fill="#fff"/><path d="'+d+'" fill="#000"/></svg>'}


var $=function(s){return document.querySelector(s)};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function sz(n){if(n==null||n<0)return'';var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return(i?n.toFixed(n<10?1:0):n)+' '+u[i]}
function dur(s){if(!isFinite(s)||s<0)return'';s=Math.round(s);if(s<60)return s+' s';var m=Math.floor(s/60);if(m<60)return m+' min';return Math.floor(m/60)+' h '+(m%60)+' min'}
function ago(t){var s=(Date.now()-t)/1000;if(s<45)return'just now';if(s<3600)return Math.round(s/60)+' min ago';if(s<86400)return Math.round(s/3600)+' h ago';return Math.round(s/86400)+' d ago'}
function buzz(n){try{if(navigator.vibrate)navigator.vibrate(n)}catch(e){}}
var tt;function toast(m,k){var t=$('#toast');t.textContent=m;t.classList.add('show');clearTimeout(tt);tt=setTimeout(function(){t.classList.remove('show')},2400);if(k==='ok')buzz(10);else if(k==='err')buzz([14,40,14])}
function copyText(t){var ok=false;try{if(navigator.clipboard){navigator.clipboard.writeText(t);ok=true}}catch(e){}if(!ok){try{var ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.focus();ta.select();ok=document.execCommand('copy');document.body.removeChild(ta)}catch(e){}}return ok}
/* ---------- native API ---------- */
var LS=getLanSharePlugin();
/* ---------- state ---------- */
var S=createState(store);
var PT=null,pollT=0;
function saveHist(){store('airlink_hist',S.xfers.filter(function(x){return x.state!=='run'&&x.state!=='verify'}).slice(-30).map(function(x){return{name:x.name,dir:x.dir,total:x.total,done:x.done,state:x.state,where:x.where,sha:x.sha,t:x.t,msg:x.msg}}))}
function applyInfo(i){S.running=!!i.running;S.port=i.port||0;S.tlsPort=i.tlsPort||0;S.fingerprint=i.fingerprint||'';S.codeExpiresAt=i.codeExpiresAt||0;S.key=i.key||'';S.ips=i.ips||[];if(S.ip>=S.ips.length)S.ip=0;S.device=i.device||''}
function url(code){var ip=S.ips[S.ip]||'phone-ip',q=[];if(code)q.push('k='+encodeURIComponent(S.key));if(S.tlsPort)q.push('tls='+S.tlsPort);if(S.fingerprint)q.push('fp='+S.fingerprint);return'http://'+ip+':'+S.port+'/'+(q.length?'?'+q.join('&'):'')}

/* ---------- icons ---------- */
function ic(p,w){return'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="'+(w||2)+'" stroke-linecap="round" stroke-linejoin="round">'+p+'</svg>'}
var I={
 copy:ic('<rect x="9" y="9" width="12" height="12" rx="3"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>'),
 plus:ic('<path d="M12 5v14M5 12h14"/>',2.2),
 close:ic('<path d="M6 6l12 12M18 6L6 18"/>',2.2),
 search:ic('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>'),
 link:ic('<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1"/>'),
 down:ic('<path d="M12 4v12M6 11l6 6 6-6M5 20h14"/>',2.2),
 up:ic('<path d="M12 20V8M6 13l6-6 6 6M5 4h14"/>',2.2),
 refresh:ic('<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>'),
 chev:ic('<path d="M9 6l6 6-6 6"/>',2.2),
 gear:ic('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',1.8),
 qr:ic('<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 14h3v3M21 14v.01M14 21h3M21 17v4"/>'),
 shield:ic('<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>'),
 key:ic('<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>')
};
function ext(n){var m=/\.([a-z0-9]{1,4})$/i.exec(n||'');return m?m[1].toUpperCase():'FILE'}
function ftHtml(n,c){return'<div class="ft '+(c||'')+'">'+esc(ext(n))+'</div>'}
var icoPower='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 3v8"/><path d="M6.3 6.6a8 8 0 1 0 11.4 0"/></svg>';

var viewApi=createViews({S:S,I:I,esc:esc,sz:sz,dur:dur,ago:ago,ftHtml:ftHtml,icoPower:icoPower,url:url,$:$,t:t});
var xferHtml=viewApi.xferHtml, filesHtml=viewApi.filesHtml, heroHtml=viewApi.heroHtml;
var devicesHtml=viewApi.devicesHtml, clipsHtml=viewApi.clipsHtml, render=viewApi.render;
var peerHtml=viewApi.peerHtml, peerFiles=viewApi.peerFiles, aboutHtml=viewApi.aboutHtml;
function refreshX(){var e=$('#xf');if(e)e.innerHTML=xferHtml()}

/* ---------- transfer events ---------- */
function findX(name,dir){for(var i=S.xfers.length-1;i>=0;i--){var x=S.xfers[i];if(x.name===name&&x.dir===dir&&(x.state==='run'||x.state==='verify'))return x}return null}
function onProgress(d){
  var dir=d.upload?'in':'out',x=findX(d.name,dir),now=Date.now();
  if(!x){x={name:d.name,dir:dir,done:0,total:d.total,state:'run',t0:now,lastT:now,lastDone:d.done,speed:0};S.xfers.push(x);render()}
  var dt=(now-x.lastT)/1000;
  if(dt>=0.5){var inst=(d.done-x.lastDone)/dt;if(inst>=0)x.speed=x.speed?x.speed*0.6+inst*0.4:inst;x.lastT=now;x.lastDone=d.done}
  x.done=d.done;x.total=d.total;
  if(dir==='out'&&d.total>0&&d.done>=d.total&&x.state==='run'){x.state='verify'}
  refreshX();
}
function onPhase(d){var x=findX(d.name,'in');if(x&&d.phase==='verify'){x.state='verify';refreshX()}}
function onReceived(d){
  var x=findX(d.name,'in');
  if(!x){x={name:d.name,dir:'in'};S.xfers.push(x)}
  x.state='done';x.done=x.total=d.size;x.where=d.where;x.sha=d.sha256;x.t=Date.now();saveHist();refreshX();toast('Received '+d.name,'ok');
}
function onSent(d){
  var x=findX(d.name,'out');
  if(!x){x={name:d.name,dir:'out',done:1,total:1};S.xfers.push(x)}
  x.state='done';x.done=x.total=Math.max(x.total||0,1);x.sha=d.sha256;x.t=Date.now();saveHist();refreshX();toast('Sent '+d.name,'ok');
}
function onPeerError(d){
  var x=findX(d.name,'in')||findX(d.name,'out');
  if(x){x.state=d.cancelled?'cancel':'err';x.msg=d.message}
  saveHist();refreshX();if(!d.cancelled)toast((d.name?d.name+': ':'')+(d.message||'Transfer failed'),'err');
}
function onStopped(i){applyInfo(i||{});S.devices=[];S.approvals=[];closeSheet();render();toast('Sharing turned off')}
function onDevices(d){S.devices=d.devices||[];render()}
function onApproval(a){showApproval(a)}
function onApprovalDone(d){S.approvals=S.approvals.filter(function(a){return a.rid!==d.rid});if($('#sw').classList.contains('on')&&$('#apv'))approvalSheet()}
function onClip(c){toast('Text from '+(c.from||'computer')+' received','ok');loadClips()}
function onShared(d){
  LS.listShared().then(function(r){S.files=r.files||[];render()});
  if(d&&d.text)loadClips();
  toast(d&&d.count?'Added '+d.count+' file'+(d.count===1?'':'s')+' to share':'Text added to clipboard','ok');
}
function loadClips(){LS.listClips().then(function(r){S.clips=r.clips||[];render()}).catch(function(){})}
try{
  LS.addListener('progress',onProgress);LS.addListener('received',onReceived);LS.addListener('sent',onSent);LS.addListener('peerError',onPeerError);
  LS.addListener('phase',onPhase);LS.addListener('stopped',onStopped);LS.addListener('devices',onDevices);LS.addListener('approval',onApproval);
  LS.addListener('approvalDone',onApprovalDone);LS.addListener('clip',onClip);LS.addListener('shared',onShared);
}catch(e){}

/* ---------- sheets ---------- */
function openSheet(html){$('#sheet').innerHTML='<div class="grab"></div>'+html;$('#sw').classList.add('on')}
function closeSheet(){$('#sw').classList.remove('on')}
function showApproval(a){
  if(!a||!a.rid)return;
  for(var i=0;i<S.approvals.length;i++)if(S.approvals[i].rid===a.rid)return;
  S.approvals.push(a);approvalSheet();buzz([20,60,20]);
}
function approvalSheet(){
  var a=S.approvals[0];if(!a){closeSheet();return}
  openSheet('<div id="apv"></div><h2>Allow this device?</h2><div class="note"><b>'+esc(a.name)+'</b> ('+esc(a.ip)+') wants to connect and exchange files with this phone. Only allow devices you recognise.</div><div class="btns"><button class="btn" data-act="deny">Deny</button><button class="btn pri" data-act="allow">Allow</button></div>'+(S.approvals.length>1?'<div class="note" style="text-align:center">'+(S.approvals.length-1)+' more waiting</div>':''));
}
function answer(allow){var a=S.approvals.shift();if(a)LS.respondApproval({rid:a.rid,allow:allow});if(S.approvals.length)approvalSheet();else closeSheet()}
function settingsSheet(){
  var idle=S.opts.idle||0;
  function seg(v,l){return'<button class="'+(idle===v?'on':'')+'" data-act="idle" data-v="'+v+'">'+l+'</button>'}
  openSheet('<h2>Settings</h2><button class="srow" data-act="tglApprove"><div><b>Ask before connecting</b><small>Approve each new device on this phone</small></div><span class="sw'+(S.opts.approve?' on':'')+'"></span></button>'
   +'<label>Turn sharing off automatically when idle</label><div class="seg">'+seg(0,'Never')+seg(15,'15 min')+seg(30,'30 min')+seg(60,'1 hour')+'</div>'
   +'<div class="note">Changes apply the next time you start sharing.</div><div class="btns"><button class="btn" data-act="closeSheet">Done</button></div>');
}
function parseLink(s){
  s=(s||'').trim();var m=/[?&]k=(\d{6})/.exec(s),key=m?m[1]:'',tm=/[?&]tls=(\d+)/.exec(s),fm=/[?&]fp=([0-9a-f]{64})/i.exec(s);
  s=s.replace(/^https?:\/\//i,'').replace(/[\/?#].*$/,'');
  var host=s,port=8080,c=s.lastIndexOf(':');
  if(c>0){host=s.slice(0,c);port=parseInt(s.slice(c+1),10)||8080}
  return{host:host,port:port,tlsPort:tm?parseInt(tm[1],10):port,fingerprint:fm?fm[1].toUpperCase():'',key:key};
}
function peersSheet(){
  if(!S.peers.length){openSheet('<h2>No phone found</h2><div class="note">Check that both phones use the same Wi-Fi, that the other phone shows <b>Sharing is on</b>, and that both run AirLink 2. You can also enter its address by hand.</div><div class="btns"><button class="btn" data-act="scan">Search again</button><button class="btn" data-act="manual">Enter address</button></div>');return}
  openSheet('<h2>Phones nearby</h2>'+S.peers.map(function(p,i){return'<button class="srow" data-act="pickPeer" data-i="'+i+'"><div><b>'+esc(p.name)+'</b><small>'+esc(p.ip)+':'+p.port+'</small></div>'+I.chev+'</button>'}).join('')+'<div class="btns"><button class="btn" data-act="scan">Search again</button><button class="btn" data-act="closeSheet">Close</button></div>');
}
function codeSheet(t){
  PT=t;openSheet('<h2>Connect to '+esc(t.name||t.host)+'</h2><div class="note">Enter the 6-digit code shown on that phone.</div>'+(t.fingerprint?'<div class="note mono" style="font-size:11px;word-break:break-all">Compare this SHA-256 fingerprint with the other phone before pairing: '+esc(t.fingerprint)+'</div>':'<div class="note">This older/manual connection uses HTTP and is <b>not encrypted</b>.</div>')+'<input id="pc_code" class="code" inputmode="numeric" maxlength="6" placeholder="\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7" autocomplete="off"><div class="err" id="pc_msg"></div><div class="btns"><button class="btn" data-act="closeSheet">Cancel</button></div>');
  setTimeout(function(){var i=$('#pc_code');if(i&&i.focus)i.focus()},120);
}
function connectPeer(t,key){
  var m=$('#pc_msg');if(m){m.style.color='var(--sub)';m.textContent='Connecting\u2026 the other phone may ask to allow you.'}
  LS.peerList({host:t.host,port:t.port,tlsPort:t.fingerprint?(t.tlsPort||t.port):t.port,fingerprint:t.fingerprint,key:key}).then(function(r){
    S.peer={host:t.host,port:t.port,tlsPort:t.fingerprint?(t.tlsPort||t.port):t.port,fingerprint:t.fingerprint,key:key,device:r.device||t.name||'Phone',files:r.files||[],lost:false};
    closeSheet();render();startPoll();toast('Connected to '+S.peer.device,'ok');
  }).catch(function(e){var m2=$('#pc_msg');if(m2){m2.style.color='';m2.textContent=(e&&e.message)||String(e)}var c=$('#pc_code');if(c)c.value=''});
}
function startPoll(){
  clearInterval(pollT);
  pollT=setInterval(function(){
    var p=S.peer;if(!p){clearInterval(pollT);return}
    LS.peerList({host:p.host,port:p.port,tlsPort:p.tlsPort,fingerprint:p.fingerprint,key:p.key}).then(function(r){
      p.lost=false;p.files=r.files||[];var f=$('#pfiles');if(f)f.innerHTML=peerFiles();var st=$('#pstat');if(st)st.textContent=p.host+':'+p.port;
    }).catch(function(){
      p.lost=true;var st=$('#pstat');if(st)st.innerHTML=esc(p.host)+':'+p.port+' \u00b7 <b style="color:var(--bad)">Connection lost</b>';
    });
  },4000);
}
function peerArgs(extra){var p=S.peer,o={host:p.host,port:p.port,tlsPort:p.tlsPort,fingerprint:p.fingerprint,key:p.key};for(var k in extra)o[k]=extra[k];return o}

/* ---------- actions ---------- */
var A={
  start:function(){LS.start({port:8080,approve:!!S.opts.approve,idleMinutes:S.opts.idle||0}).then(function(i){applyInfo(i);S.devices=[];S.clips=[];render();loadClips()}).catch(function(e){toast('Could not start: '+((e&&e.message)||e),'err')})},
  stop:function(){LS.stop().then(function(i){applyInfo(i);S.devices=[];S.approvals=[];render()}).catch(function(){})},
  ip:function(b){S.ip=+b.dataset.i;render()},
  copyLink:function(){toast(copyText(url(false))?'Link copied':'Copy failed','ok')},
  copyFull:function(){toast(copyText(url(true))?'Link and code copied':'Copy failed','ok')},
  qr:function(){var u=url(true);openSheet('<h2>Scan to connect</h2><div class="note">Browser connections use HTTP and are <b>not encrypted</b>. The link also includes the TLS port and SHA-256 certificate fingerprint for compatible AirLink clients.</div><div class="note">Pairing code expires in 5 minutes and works once.</div><div class="qrbox">'+qrSvg(u,240)+'</div><div class="note mono" style="text-align:center;font-size:11.5px;word-break:break-all">'+esc(u)+'</div><div class="btns"><button class="btn" data-act="closeSheet">Done</button></div>')},
  newCode:function(){LS.rotateCode().then(function(i){applyInfo(i);S.devices=[];render();toast('New pairing code created. Trusted devices can reconnect.','ok')})},
  revoke:function(b){LS.revokeDevice({id:b.dataset.id}).then(function(r){S.devices=r.devices||[];render();toast('Device removed')})},
  allow:function(){answer(true)},deny:function(){answer(false)},
  settings:settingsSheet,
  tglApprove:function(){S.opts.approve=!S.opts.approve;store('airlink_opts',S.opts);settingsSheet();render()},
  idle:function(b){S.opts.idle=+b.dataset.v;store('airlink_opts',S.opts);settingsSheet()},
  cancel:function(b){var n=b.dataset.name;LS.cancel({name:n});var x=findX(n,'in')||findX(n,'out');if(x){x.state='cancel';x.msg='Cancelled'}saveHist();refreshX()},
  clearHist:function(){S.xfers=S.xfers.filter(function(x){return x.state==='run'||x.state==='verify'});saveHist();render()},
  clipSend:function(){var i=$('#clip_in'),t=i?i.value.trim():'';if(!t){toast('Type something first','err');return}LS.addClip({text:t}).then(function(r){S.clips=r.clips||[];i.value='';render();toast('Ready on your computer','ok')})},
  clipPaste:function(){try{navigator.clipboard.readText().then(function(t){var i=$('#clip_in');if(i&&t)i.value=t}).catch(function(){toast('Long-press the box to paste','err')})}catch(e){toast('Long-press the box to paste','err')}},
  clipCopy:function(b){var c=S.clips[+b.dataset.i];if(c)toast(copyText(c.text)?'Copied':'Copy failed','ok')},
  clipClear:function(){LS.clearClips().then(function(){S.clips=[];render()})},
  pick:function(){LS.pickFiles().then(function(r){S.files=r.files||[];render()}).catch(function(){toast('Could not open the file list','err')})},
  rm:function(b){LS.removeShared({id:b.dataset.id}).then(function(r){S.files=r.files||[];render()})},
  clear:function(){LS.clearShared().then(function(){S.files=[];render()})},
  scan:function(){
    openSheet('<h2>Searching nearby</h2><div class="spin"></div><div class="note" style="text-align:center">On the other phone, open AirLink and tap <b>Start sharing</b>.</div>');
    LS.scan().then(function(r){S.peers=r.peers||[];peersSheet()}).catch(function(e){openSheet('<h2>Could not search</h2><div class="note">'+esc((e&&e.message)||e)+'</div><div class="btns"><button class="btn pri" data-act="manual">Enter address</button><button class="btn" data-act="closeSheet">Close</button></div>')});
  },
  pickPeer:function(b){var p=S.peers[+b.dataset.i];if(p)codeSheet({host:p.ip,port:p.httpPort||p.port,tlsPort:p.port,fingerprint:p.fingerprint,name:p.name})},
  manual:function(){openSheet('<h2>Enter address</h2><div class="note">Enter the address shown on the other phone.</div><label>Address<input class="f" id="m_link" placeholder="192.168.1.5:8080" autocapitalize="off" autocorrect="off"></label><label>Code<input class="f" id="m_code" inputmode="numeric" maxlength="6" placeholder="\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7"></label><div class="err" id="pc_msg"></div><div class="btns"><button class="btn pri" data-act="manualGo">Connect</button><button class="btn" data-act="closeSheet">Cancel</button></div>')},
  manualGo:function(){
    var t=parseLink($('#m_link').value),code=($('#m_code').value||'').replace(/\D/g,'')||t.key;
    if(!t.host){$('#pc_msg').textContent='Enter the address';return}
    if(code.length!==6){$('#pc_msg').textContent='Enter the 6-digit code';return}
    t.name=t.host;connectPeer(t,code);
  },
  closeSheet:closeSheet,
  pget:function(b){var f=S.peer&&S.peer.files[+b.dataset.i];if(!f)return;LS.peerDownload(peerArgs({id:f.id,name:f.name})).then(function(){toast('Getting '+f.name+'\u2026')}).catch(function(e){toast((e&&e.message)||'Could not start','err')})},
  pall:function(){var p=S.peer;if(!p||!p.files.length){toast('No files to get','err');return}p.files.forEach(function(f){LS.peerDownload(peerArgs({id:f.id,name:f.name}))});toast('Getting '+p.files.length+' file'+(p.files.length===1?'':'s')+'\u2026')},
  psend:function(){LS.pickAndSend(peerArgs({})).then(function(r){if(r&&r.count)toast('Sending '+r.count+' file'+(r.count===1?'':'s')+'\u2026')}).catch(function(e){toast((e&&e.message)||'Could not send','err')})},
  prefresh:function(){var p=S.peer;if(!p)return;LS.peerList({host:p.host,port:p.port,tlsPort:p.tlsPort,fingerprint:p.fingerprint,key:p.key}).then(function(r){p.lost=false;p.files=r.files||[];render();toast('Updated')}).catch(function(e){p.lost=true;render();toast((e&&e.message)||'Connection lost','err')})},
  pdisc:function(){clearInterval(pollT);S.peer=null;render()}
};
document.addEventListener('input',function(e){
  if(e.target.id==='pc_code'){var v=e.target.value.replace(/\D/g,'');e.target.value=v;if(v.length===6&&PT)connectPeer(PT,v)}
});
document.addEventListener('click',function(e){
  if(e.target.id==='sw'){if(!S.approvals.length)closeSheet();return}
  var b=e.target.closest('[data-act]');
  if(e.target.closest('button,a.btn'))buzz(6);
  if(b&&A[b.dataset.act])A[b.dataset.act](b);
});
document.addEventListener('visibilitychange',function(){
  if(document.hidden||!S.running)return;
  LS.pendingApprovals().then(function(r){(r.pending||[]).forEach(showApproval)}).catch(function(){});
  LS.devices().then(function(r){S.devices=r.devices||[];render()}).catch(function(){});
});

LS.status().then(function(i){applyInfo(i);return LS.listShared&&LS.listShared()}).then(function(r){if(r&&r.files)S.files=r.files;render();if(S.running){loadClips();LS.devices().then(function(r2){S.devices=r2.devices||[];render()});LS.pendingApprovals().then(function(r3){(r3.pending||[]).forEach(showApproval)})}}).catch(function(){render()});
render();
setTimeout(function(){var s=$('#splash');s.classList.add('hide');setTimeout(function(){s.style.display='none'},600)},1300);
