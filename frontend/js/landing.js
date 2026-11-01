/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Landing Page Interactive Node Canvas & Quick Test Scripts
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Interactive Cybersecurity Network Canvas Animation
  const canvas = document.getElementById('network-canvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    });

    const particles = [];
    const particleCount = Math.min(Math.floor(width / 22), 65);
    const maxDistance = 140;

    let mouse = { x: null, y: null };
    window.addEventListener('mousemove', (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    });
    window.addEventListener('mouseleave', () => {
      mouse.x = null;
      mouse.y = null;
    });

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.8,
        vy: (Math.random() - 0.5) * 0.8,
        radius: Math.random() * 2 + 1.2,
        isMalicious: Math.random() < 0.15 // some red nodes representing blocked threats!
      });
    }

    const animate = () => {
      ctx.clearRect(0, 0, width, height);

      // Draw particle connections
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            const opacity = 1 - (dist / maxDistance);
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);

            if (particles[i].isMalicious || particles[j].isMalicious) {
              ctx.strokeStyle = `rgba(255, 51, 102, ${opacity * 0.22})`;
            } else {
              ctx.strokeStyle = `rgba(0, 240, 255, ${opacity * 0.2})`;
            }
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      // Draw particles & update position
      particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;

        // Mouse attraction / interaction
        if (mouse.x !== null) {
          const mdx = p.x - mouse.x;
          const mdy = p.y - mouse.y;
          const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
          if (mdist < 120) {
            p.x += (mdx / mdist) * 1.5;
            p.y += (mdy / mdist) * 1.5;
          }
        }

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        if (p.isMalicious) {
          ctx.fillStyle = '#ff3366';
          ctx.shadowColor = '#ff3366';
          ctx.shadowBlur = 8;
        } else {
          ctx.fillStyle = '#00f0ff';
          ctx.shadowColor = '#00f0ff';
          ctx.shadowBlur = 8;
        }
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      requestAnimationFrame(animate);
    };

    animate();
  }

  // 2. Navbar Scroll Effect
  const nav = document.querySelector('.landing-nav');
  if (nav) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 40) {
        nav.classList.add('scrolled');
      } else {
        nav.classList.remove('scrolled');
      }
    });
  }

  // 3. Quick Domain Test Demo in Hero
  const heroInput = document.getElementById('heroDomainInput');
  const heroBtn = document.getElementById('heroCheckBtn');
  const heroResult = document.getElementById('heroCheckResult');

  const executeHeroCheck = async (domainToTest) => {
    const domain = domainToTest || (heroInput ? heroInput.value.trim() : '');
    if (!domain) {
      if (heroResult) {
        heroResult.innerHTML = `<span class="text-malicious"><i class="fa-solid fa-triangle-exclamation me-1"></i>Please enter a domain name.</span>`;
      }
      return;
    }

    if (heroBtn) {
      heroBtn.disabled = true;
      heroBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Checking...`;
    }
    if (heroResult) {
      heroResult.innerHTML = `<span class="text-cyan"><i class="fa-solid fa-radar fa-spin me-1"></i> Consulting threat intelligence engine...</span>`;
    }

    try {
      const result = await CyberApiService.checkDomain(domain);
      let statusColor = result.status === 'SAFE' ? 'safe' : result.status === 'MALICIOUS' ? 'malicious' : 'suspicious';
      let icon = result.status === 'SAFE' ? 'fa-circle-check' : result.status === 'MALICIOUS' ? 'fa-shield-virus' : 'fa-triangle-exclamation';

      if (heroResult) {
        heroResult.innerHTML = `
          <div class="d-inline-flex align-items-center gap-2 p-2 px-3 rounded" style="background: rgba(11, 20, 39, 0.9); border: 1px solid var(--color-${statusColor}-border);">
            <span class="status-pulse pulse-${statusColor}"></span>
            <span class="text-${statusColor} fw-bold font-mono">${result.status}:</span>
            <span class="text-main font-mono">${result.domain}</span>
            <span class="text-dim">|</span>
            <span class="text-muted" style="font-size: 0.8rem;">Risk Score: ${result.riskScore}/100</span>
            <a href="domain-checker.html?domain=${encodeURIComponent(result.domain)}" class="btn-cyber-primary btn-cyber-sm ms-2" style="padding: 0.2rem 0.6rem; font-size: 0.75rem;">Full Report</a>
          </div>
        `;
      }
    } catch (e) {
      if (heroResult) {
        heroResult.innerHTML = `<span class="text-malicious">${e.message}</span>`;
      }
    } finally {
      if (heroBtn) {
        heroBtn.disabled = false;
        heroBtn.innerHTML = `Inspect Domain <i class="fa-solid fa-arrow-right"></i>`;
      }
    }
  };

  if (heroBtn) {
    heroBtn.addEventListener('click', () => executeHeroCheck());
  }

  if (heroInput) {
    heroInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executeHeroCheck();
    });
  }

  // Quick sample chips in Hero
  const sampleBadges = document.querySelectorAll('.hero-sample-chip');
  sampleBadges.forEach(badge => {
    badge.addEventListener('click', () => {
      const domain = badge.getAttribute('data-domain');
      if (heroInput) heroInput.value = domain;
      executeHeroCheck(domain);
    });
  });
});

