/* Theme switcher. The <head> snippet in _layouts/default.html applies the
   saved theme before first paint; this file builds the menu and handles changes. */
(function () {
  var THEMES = [
    { id: 'auto',     name: 'Auto (system)' },
    { id: 'terminal', name: 'Terminal', sw: ['#0B0F14', '#C9A227', '#E7ECEF'] },
    { id: 'paper',    name: 'Paper',    sw: ['#F7F5EF', '#8A6400', '#1A1D21'] },
    { id: 'phosphor', name: 'Phosphor', sw: ['#050805', '#4AF626', '#C8F7C5'] },
    { id: 'midnight', name: 'Midnight', sw: ['#17181F', '#BD93F9', '#F8F8F2'] },
    { id: 'nord',     name: 'Nord',     sw: ['#2E3440', '#88C0D0', '#ECEFF4'] }
  ];
  var KEY = 'gt-theme';
  var DEFAULT = 'terminal';
  var root = document.documentElement;
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;

  function find(id) { for (var i = 0; i < THEMES.length; i++) if (THEMES[i].id === id) return THEMES[i]; return null; }
  function load() { try { var v = localStorage.getItem(KEY); return find(v) ? v : DEFAULT; } catch (e) { return DEFAULT; } }
  function save(v) { try { localStorage.setItem(KEY, v); } catch (e) {} }
  function resolve(choice) { return choice === 'auto' ? (mq && mq.matches ? 'paper' : 'terminal') : choice; }

  function swatchFor(choice) {
    var colours = choice === 'auto'
      ? [find('terminal').sw[0], find('terminal').sw[1], find('paper').sw[0]]
      : find(choice).sw;
    var s = document.createElement('span');
    s.className = 'swatch';
    s.setAttribute('aria-hidden', 'true');
    colours.forEach(function (c) { var i = document.createElement('i'); i.style.background = c; s.appendChild(i); });
    return s;
  }

  var current = load();

  function apply(choice) {
    var t = resolve(choice);
    if (t === 'terminal') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', t);
  }

  var wrap = document.querySelector('.theme-switch');
  if (!wrap) { apply(current); return; }
  var toggle = wrap.querySelector('.theme-toggle');
  var menu = wrap.querySelector('.theme-menu');
  var label = toggle.querySelector('.label');

  var head = document.createElement('div');
  head.className = 'menu-label';
  head.textContent = 'Theme';
  head.setAttribute('aria-hidden', 'true');
  menu.appendChild(head);

  var items = THEMES.map(function (t) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'theme-option';
    b.setAttribute('role', 'menuitemradio');
    b.setAttribute('tabindex', '-1');
    b.dataset.theme = t.id;
    b.appendChild(swatchFor(t.id));
    b.appendChild(document.createTextNode(t.name));
    b.addEventListener('click', function () { choose(t.id); close(true); });
    menu.appendChild(b);
    return b;
  });

  function render() {
    var old = toggle.querySelector('.swatch');
    if (old) old.remove();
    toggle.insertBefore(swatchFor(current), label);
    label.textContent = find(current).name.replace(' (system)', '');
    toggle.setAttribute('aria-label', 'Change theme (current: ' + find(current).name + ')');
    items.forEach(function (b) { b.setAttribute('aria-checked', String(b.dataset.theme === current)); });
  }

  function choose(id) { current = id; save(id); apply(id); render(); }

  function open() {
    menu.hidden = false;
    toggle.setAttribute('aria-expanded', 'true');
    var sel = menu.querySelector('[aria-checked="true"]') || items[0];
    sel.focus();
  }
  function close(refocus) {
    if (menu.hidden) return;
    menu.hidden = true;
    toggle.setAttribute('aria-expanded', 'false');
    if (refocus) toggle.focus();
  }

  toggle.addEventListener('click', function () { if (menu.hidden) open(); else close(false); });
  toggle.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); open(); }
  });
  menu.addEventListener('keydown', function (e) {
    var i = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    else if (e.key === 'Home') { e.preventDefault(); items[0].focus(); }
    else if (e.key === 'End') { e.preventDefault(); items[items.length - 1].focus(); }
    else if (e.key === 'Escape') { e.preventDefault(); close(true); }
    else if (e.key === 'Tab') { close(false); }
  });
  document.addEventListener('click', function (e) { if (!wrap.contains(e.target)) close(false); });

  if (mq) {
    var onChange = function () { if (current === 'auto') apply('auto'); };
    if (mq.addEventListener) mq.addEventListener('change', onChange); else if (mq.addListener) mq.addListener(onChange);
  }

  apply(current);
  render();
  wrap.hidden = false;
})();
