(() => {
  'use strict';
  const panel = document.querySelector('.panel');
  const art = document.querySelector('.background-art');
  const logo = document.querySelector('.logo');
  const pupil = document.querySelector('#tracking-pupil');
  const motionButton = document.querySelector('#motion');
  if (!panel || !art || !logo || !pupil || !motionButton) return;

  const preference = matchMedia('(prefers-reduced-motion: reduce)');
  let enabled = !preference.matches;
  let frame = 0;
  let pointer = null;
  let reveal = [];

  function resetPointer() {
    cancelAnimationFrame(frame);
    frame = 0;
    pointer = null;
    art.style.setProperty('--drift-x', '0px');
    art.style.setProperty('--drift-y', '0px');
    pupil.removeAttribute('transform');
    panel.querySelectorAll('.corner-pupil').forEach((eye) => eye.removeAttribute('transform'));
  }

  function clearRipples() {
    panel.querySelectorAll('.doodle-ripple').forEach((node) => node.remove());
  }

  function refreshMotion() {
    panel.classList.toggle('motion-off', !enabled);
    motionButton.setAttribute('aria-pressed', String(enabled));
    motionButton.textContent = preference.matches
      ? 'Reduced motion'
      : enabled
      ? 'Motion on'
      : 'Motion off';
    motionButton.disabled = preference.matches;
    if (!enabled) {
      resetPointer();
      clearRipples();
      reveal.forEach((animation) => animation.cancel());
      reveal = [];
    }
  }

  motionButton.addEventListener('click', () => {
    enabled = !enabled;
    refreshMotion();
  });

  preference.addEventListener('change', () => {
    enabled = !preference.matches;
    refreshMotion();
  });

  function updatePointer() {
    frame = 0;
    if (!enabled || !pointer || document.hidden) return;
    const bounds = panel.getBoundingClientRect();
    const x = Math.max(-1, Math.min(1, ((pointer.x - bounds.left) / bounds.width) * 2 - 1));
    const y = Math.max(
      -1,
      Math.min(1, ((pointer.y - bounds.top) / Math.min(bounds.height, 600)) * 2 - 1)
    );
    art.style.setProperty('--drift-x', (x * 3).toFixed(2) + 'px');
    art.style.setProperty('--drift-y', (y * 2).toFixed(2) + 'px');

    panel.querySelectorAll('.corner-pupil').forEach((eye) => {
      const b = eye.getBoundingClientRect();
      const dx = pointer.x - b.left - b.width / 2;
      const dy = pointer.y - b.top - b.height / 2;
      const length = Math.hypot(dx, dy) || 1;
      eye.setAttribute(
        'transform',
        `translate(${((dx / length) * 3).toFixed(2)} ${((dy / length) * 2).toFixed(2)})`
      );
    });
    const eye = logo.getBoundingClientRect();
    const dx = pointer.x - eye.left - eye.width / 2;
    const dy = pointer.y - eye.top - eye.height / 2;
    const distance = Math.hypot(dx, dy) || 1;
    pupil.setAttribute(
      'transform',
      `translate(${((dx / distance) * 7).toFixed(2)} ${((dy / distance) * 2).toFixed(2)})`
    );
  }

  panel.addEventListener(
    'pointermove',
    (event) => {
      if (!enabled || event.pointerType === 'touch') return;
      pointer = { x: event.clientX, y: event.clientY };
      if (!frame) frame = requestAnimationFrame(updatePointer);
    },
    { passive: true }
  );
  panel.addEventListener('pointerleave', resetPointer);

  function ripple(target, event) {
    if (!enabled || document.hidden) return;
    const bounds = target.getBoundingClientRect();
    const x = event.clientX - bounds.left;
    const y = event.clientY - bounds.top;
    clearRipples();
    for (let i = 0; i < 2; i++) {
      const ring = document.createElement('span');
      ring.className = 'doodle-ripple' + (i ? ' secondary' : '');
      ring.setAttribute('aria-hidden', 'true');
      ring.style.left = x + 'px';
      ring.style.top = y + 'px';
      target.append(ring);
      ring.addEventListener('animationend', () => ring.remove(), { once: true });
      setTimeout(() => ring.remove(), 1100);
    }
  }

  const assessmentEl = document.querySelector('.assessment');
  const primaryEl = document.querySelector('.primary');
  if (assessmentEl) {
    assessmentEl.addEventListener('pointerdown', (event) => {
      if (event.button === 0) ripple(event.currentTarget, event);
    });
  }
  if (primaryEl) {
    primaryEl.addEventListener('pointerdown', (event) => {
      if (event.button === 0) ripple(event.currentTarget, event);
    });
  }

  panel.querySelectorAll('.report, .reason').forEach((details) => {
    details.addEventListener('toggle', (event) => {
      if (event.target !== details || !details.open || !enabled) return;
      reveal = reveal.filter((animation) => animation.playState !== 'finished');
      if (typeof details.animate !== 'function') return;
      const content =
        details.querySelector('.detail-body') ||
        details.querySelector('.report-intro') ||
        details.querySelector('p');
      if (content) {
        reveal.push(
          content.animate(
            [
              { opacity: 0.25, transform: 'translateY(-3px)' },
              { opacity: 1, transform: 'translateY(0)' }
            ],
            { duration: 200, easing: 'ease-out' }
          )
        );
      }
    });
  });

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      resetPointer();
      clearRipples();
    }
  });
  refreshMotion();
})();
