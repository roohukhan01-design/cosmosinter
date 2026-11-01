export function applyTheme(mode) {
  var selected = mode || 'auto';
  try { selected = mode || localStorage.getItem('airlink_theme') || 'auto'; } catch (_) {}
  function update() {
    var dark = selected === 'dark' || (selected === 'auto' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  }
  update();
  if (window.matchMedia) {
    var media = window.matchMedia('(prefers-color-scheme: dark)');
    if (media.addEventListener) media.addEventListener('change', function(){ if (selected === 'auto') update(); });
  }
}
applyTheme();
