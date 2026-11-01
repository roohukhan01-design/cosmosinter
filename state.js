export function createState(store) {
  var state = { running:false, port:0, tlsPort:0, fingerprint:'', codeExpiresAt:0, key:'', ips:[], ip:0, files:[], xfers:[], device:'', peer:null, peers:[], devices:[], clips:[], approvals:[], opts:store('airlink_opts') || {approve:true,idle:0} };
  (store('airlink_hist') || []).forEach(function(item) {
    if (item.state === 'run' || item.state === 'verify') item.state = 'err';
    state.xfers.push(item);
  });
  return state;
}
