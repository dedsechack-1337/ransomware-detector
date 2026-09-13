// matrix-bg.js
// -------------
// Purely decorative "digital rain" canvas behind the dashboard, in
// keeping with the dark techno theme. Cheap to run (small font, low
// frame rate) and never intercepts pointer events.

(function () {
  const canvas = document.getElementById('matrix-bg');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const CHARS = '01<>/{}[]#$%&ABCDEF0123456789';
  const FONT_SIZE = 15;
  let columns = 0;
  let drops = [];

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.ceil(canvas.width / FONT_SIZE);
    drops = new Array(columns).fill(0).map(() => Math.floor(Math.random() * -40));
  }

  function draw() {
    ctx.fillStyle = 'rgba(6, 11, 16, 0.18)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.font = FONT_SIZE + 'px "IBM Plex Mono", monospace';
    for (let i = 0; i < columns; i++) {
      const char = CHARS[Math.floor(Math.random() * CHARS.length)];
      const x = i * FONT_SIZE;
      const y = drops[i] * FONT_SIZE;

      const isHead = Math.random() > 0.94;
      ctx.fillStyle = isHead ? 'rgba(53, 240, 164, 0.85)' : 'rgba(74, 212, 240, 0.35)';
      ctx.fillText(char, x, y);

      if (y > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }

  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 60);
})();
