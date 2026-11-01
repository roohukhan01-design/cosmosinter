export function createViews(ctx) {
  var S=ctx.S, I=ctx.I, esc=ctx.esc, sz=ctx.sz, dur=ctx.dur, ago=ctx.ago;
  var ftHtml=ctx.ftHtml, icoPower=ctx.icoPower, url=ctx.url, $=ctx.$, t=ctx.t;
/* ---------- views ---------- */
function xferHtml(){
  if(!S.xfers.length)return'<div class="empty">No transfers yet.</div>';
  return S.xfers.slice().reverse().slice(0,25).map(function(x){
    var run=x.state==='run'||x.state==='verify';
    var pc=x.total>0?Math.min(100,x.done/x.total*100):(x.state==='done'?100:0);
    var st=x.state==='done'?'<span class="tag ok">'+(x.sha?'Verified':'Done')+'</span>':x.state==='err'?'<span class="tag er">Failed</span>':x.state==='cancel'?'<span class="tag">Cancelled</span>':x.state==='verify'?'<span class="tag">Checking</span>':'<span class="tag">'+Math.round(pc)+'%</span>';
    var bar=run?'<div class="bar'+(x.state==='verify'?' ind':'')+'"><i style="width:'+(x.state==='verify'?100:pc)+'%"></i></div>':'';
    var sub=(x.dir==='in'?'Received':'Sent')+' \u00b7 '+sz(x.total>0?x.total:x.done);
    if(run&&x.state==='run'&&x.speed>0){sub=(x.dir==='in'?'Receiving':'Sending')+' \u00b7 '+sz(x.speed)+'/s';if(x.total>0&&x.speed>1)sub+=' \u00b7 '+dur((x.total-x.done)/x.speed)+' left'}
    else if(x.state==='run')sub=(x.dir==='in'?'Receiving':'Sending')+' \u00b7 '+sz(x.total>0?x.total:x.done);
    else if(x.state==='verify')sub='Checking the file is intact';
    else if(x.state==='done'&&x.where)sub+=' \u00b7 '+esc(x.where);
    else if(x.state==='err'&&x.msg)sub=esc(x.msg);
    if(x.state==='done'&&x.t)sub+=' \u00b7 '+ago(x.t);
    var cx=x.state==='run'?'<button class="x" data-act="cancel" data-name="'+esc(x.name)+'" aria-label="Cancel">'+I.close+'</button>':'';
    return'<div class="row">'+ftHtml(x.name,x.dir==='in'?'in':'out')+'<div class="nm"><b>'+esc(x.name)+'</b><small>'+sub+'</small>'+bar+'</div>'+st+cx+'</div>';
  }).join('');
}
function filesHtml(){
  if(!S.files.length)return'<div class="empty">Choose files to share with your computer.</div>';
  return S.files.map(function(f){return'<div class="row">'+ftHtml(f.name)+'<div class="nm"><b>'+esc(f.name)+'</b><small>'+sz(f.size)+'</small></div><button class="x" data-act="rm" data-id="'+esc(f.id)+'" aria-label="Remove">'+I.close+'</button></div>'}).join('');
}
function heroHtml(){
  if(!S.running)return'<div class="card hero" id="hero"><div class="pwr"><button class="pw" data-act="start" aria-label="Start sharing">'+icoPower+'</button></div><h2>Ready to share</h2><p>Move files between your phone and computer over Wi-Fi. No internet, no cloud.</p><button class="btn pri big" data-act="start">Start sharing</button><div class="trust">'+I.shield+'<span>'+(S.opts.approve?'You approve every device that connects':'Anyone with the code can connect')+'</span></div></div>';
  var ips=S.ips.length>1?'<div class="ips">'+S.ips.map(function(ip,i){return'<button class="'+(i===S.ip?'on':'')+'" data-act="ip" data-i="'+i+'">'+esc(ip)+'</button>'}).join('')+'</div>':'';
  var dg=String(S.key||'').split('').map(function(d){return'<span class="mono">'+esc(d)+'</span>'}).join('');
  return'<div class="card hero on" id="hero"><div class="pwr"><button class="pw" data-act="stop" aria-label="Stop sharing">'+icoPower+'</button></div><h2>Sharing is on</h2><p>Open this address in a browser on your computer, or scan the QR code.</p>'
  +'<div class="lk"><small>Address</small><div class="u mono">'+esc(S.ips.length?url(false):'No Wi-Fi found')+'</div><small style="margin-top:16px">Code</small><div class="digits">'+dg+'</div>'+ips+'</div>'
  +'<div class="note">'+t('pairingExpiry')+' Browser links use unencrypted HTTP.</div>'
  +(S.fingerprint?'<div class="note mono" style="font-size:11px;word-break:break-all">TLS SHA-256 fingerprint · '+esc(S.fingerprint)+'</div>':'')
  +'<div class="btns"><button class="btn" data-act="copyLink">'+I.link+'Copy link</button><button class="btn" data-act="qr">'+I.qr+'QR code</button></div>'
  +'<div class="btns" style="margin-top:6px"><button class="btn" data-act="copyFull">'+I.copy+'Link + code</button><button class="btn" data-act="newCode">'+I.key+'New code</button></div>'
  +'<button class="btn big dng" data-act="stop" style="margin-top:6px">Stop sharing</button></div>';
}
function devicesHtml(){
  if(!S.running)return'';
  var rows=S.devices.length?S.devices.map(function(d){var meta=d.ip==='Previously paired'?'Saved on this phone':esc(d.ip)+' \u00b7 paired '+ago(d.since);return'<div class="row"><div class="ft">'+esc((d.name||'?').slice(0,2).toUpperCase())+'</div><div class="nm"><b>'+esc(d.name)+'</b><small>'+meta+'</small></div><button class="x tx" data-act="revoke" data-id="'+esc(d.id)+'">Remove</button></div>'}).join(''):'<div class="empty">No trusted devices yet.</div>';
  return'<div class="card"><h3>Trusted devices</h3>'+rows+'</div>';
}
function clipsHtml(){
  if(!S.running)return'';
  var list=S.clips.length?S.clips.map(function(c,i){return'<div class="row"><div class="nm"><b class="clip">'+esc(c.text)+'</b><small>'+esc(c.from||'')+' \u00b7 '+ago(c.ts)+'</small></div><button class="x" data-act="clipCopy" data-i="'+i+'" aria-label="Copy">'+I.copy+'</button></div>'}).join(''):'<div class="empty">Text you send or receive shows up here.</div>';
  return'<div class="card"><h3>Clipboard</h3><textarea id="clip_in" class="f ta" rows="2" placeholder="Type or paste text to send to your computer"></textarea><div class="btns"><button class="btn" data-act="clipPaste">Paste</button><button class="btn pri" data-act="clipSend">Send</button></div><div id="cliplist" style="margin-top:8px">'+list+'</div>'+(S.clips.length?'<div class="btns"><button class="btn dng" data-act="clipClear">Clear all</button></div>':'')+'</div>';
}
function render(){
  $('#pill').textContent=S.running?(S.devices.length?S.devices.length+(S.devices.length===1?' device':' devices'):'Sharing'):'Off';$('#pill').classList.toggle('on',S.running);
  var ci=$('#clip_in'),keep=ci?ci.value:'';
  var h='';
  h+=heroHtml();
  h+=devicesHtml();
  h+=peerHtml();
  h+='<div class="card"><h3>Send to computer</h3><div id="files">'+filesHtml()+'</div><div class="btns"><button class="btn" data-act="pick">'+I.plus+'Add files</button>'+(S.files.length?'<button class="btn dng" data-act="clear">Clear all</button>':'')+'</div><div class="note">Tip: share files to AirLink from any app using Android\u2019s Share button.</div></div>';
  h+=clipsHtml();
  h+='<div class="card"><h3>Activity</h3><div id="xf">'+xferHtml()+'</div>'+(S.xfers.length?'<div class="btns"><button class="btn dng" data-act="clearHist">Clear history</button></div>':'')+'</div>';
  h+='<div class="card"><h3>How it works</h3><ol class="steps"><li>Connect both devices to the same Wi-Fi, or use this phone\u2019s hotspot.</li><li>Tap Start sharing.</li><li>Open the address on your computer, enter the code, and approve it here.</li></ol><div class="note">Received files are saved to Downloads/AirLink. Transfers resume if Wi-Fi drops and every file is checked for damage.</div></div>';
  h+=aboutHtml();
  var v=$('#view'),top=v.scrollTop;v.innerHTML=h;v.scrollTop=top;
  var n=$('#clip_in');if(n&&keep)n.value=keep;
}
function peerHtml(){
  if(!S.peer)return'<div class="card"><h3>Phone to phone</h3><div class="note" style="margin:0 0 4px">Start sharing on the other phone, then find it here.</div><div class="btns"><button class="btn" data-act="scan">'+I.search+'Find phones</button><button class="btn" data-act="manual">Enter address</button></div></div>';
  var p=S.peer;
  return'<div class="card"><h3>Connected \u00b7 '+esc(p.device)+'</h3><div class="note mono" style="margin:0 0 10px;font-size:12px" id="pstat">'+esc(p.host)+':'+p.port+(p.lost?' \u00b7 <b style="color:var(--bad)">Connection lost</b>':'')+'</div><div id="pfiles">'+peerFiles()+'</div><div class="btns"><button class="btn pri" data-act="pall">'+I.down+'Get all</button><button class="btn" data-act="psend">'+I.up+'Send files</button></div><div class="btns" style="margin-top:6px"><button class="btn" data-act="prefresh">'+I.refresh+'Refresh</button><button class="btn dng" data-act="pdisc">Disconnect</button></div></div>';
}
function peerFiles(){
  var p=S.peer;if(!p)return'';
  if(!p.files.length)return'<div class="empty">Nothing shared yet. You can still send files.</div>';
  return p.files.map(function(f,i){return'<div class="row">'+ftHtml(f.name)+'<div class="nm"><b>'+esc(f.name)+'</b><small>'+sz(f.size)+'</small></div><button class="dl" data-act="pget" data-i="'+i+'">Get</button></div>'}).join('');
}
function aboutHtml(){
  var mail='roohukhan01@gmail.com';
  return'<div class="foot">AirLink 3.0 \u00b7 by Roohu<br><a href="mailto:'+mail+'?subject=AirLink%20support">Contact support</a></div>';
}
  return { xferHtml:xferHtml, filesHtml:filesHtml, heroHtml:heroHtml, devicesHtml:devicesHtml, clipsHtml:clipsHtml, render:render, peerHtml:peerHtml, peerFiles:peerFiles, aboutHtml:aboutHtml };
}
