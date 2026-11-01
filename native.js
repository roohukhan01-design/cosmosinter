function unavailable() { return Promise.reject(new Error('AirLink native sharing is available in the installed Android app.')); }
export function getLanSharePlugin() {
  try {
    var C = window.Capacitor;
    var plugin = C && C.Plugins && C.Plugins.LanShare;
    if (!plugin && C && C.registerPlugin) plugin = C.registerPlugin('LanShare');
    if (plugin) return plugin;
  } catch (_) {}
  var names = ['start','stop','status','devices','revokeDevice','rotateCode','respondApproval','pendingApprovals','listClips','addClip','clearClips','cancel','pickFiles','removeShared','clearShared','listShared','scan','peerList','peerDownload','pickAndSend'];
  var api = { addListener: function(){ return Promise.resolve({ remove: function(){} }); } };
  names.forEach(function(name){ api[name] = unavailable; });
  return api;
}
