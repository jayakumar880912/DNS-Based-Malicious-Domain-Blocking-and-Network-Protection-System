/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Global UI Interactions: Sidebar, Topbar, Notifications, Modals & Toast Utilities
 */

const CyberUI = (() => {
  // Initialize Toast Container if absent
  const ensureToastContainer = () => {
    let container = document.getElementById('cyber-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'cyber-toast-container';
      container.className = 'toast-container-cyber';
      document.body.appendChild(container);
    }
    return container;
  };

  return {
    /**
     * Show a sleek cyber toast notification
     * @param {string} message - Message text
     * @param {string} type - 'success' | 'danger' | 'warning' | 'info'
     * @param {number} duration - ms to stay visible
     */
    showToast(message, type = 'info', duration = 3500) {
      const container = ensureToastContainer();
      const toast = document.createElement('div');
      toast.className = `toast-cyber toast-${type}`;

      let icon = 'fa-circle-info';
      if (type === 'success') icon = 'fa-circle-check';
      if (type === 'danger') icon = 'fa-triangle-exclamation';
      if (type === 'warning') icon = 'fa-triangle-exclamation';

      toast.innerHTML = `
        <i class="fa-solid ${icon} text-${type === 'danger' ? 'malicious' : type === 'success' ? 'safe' : type === 'warning' ? 'suspicious' : 'cyan'} fa-lg"></i>
        <div style="flex: 1;">
          <div style="font-weight: 600; font-size: 0.88rem;">${type.toUpperCase()}</div>
          <div style="font-size: 0.82rem; color: var(--text-muted);">${message}</div>
        </div>
        <button type="button" class="btn-close-cyber" style="font-size: 0.9rem;" onclick="this.parentElement.remove()">
          <i class="fa-solid fa-xmark"></i>
        </button>
      `;

      container.appendChild(toast);

      setTimeout(() => {
        toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 400);
      }, duration);
    },

    /**
     * Animate numeric counters from 0 to target
     */
    animateCounter(element, target, duration = 1200) {
      if (!element) return;
      const start = 0;
      const startTime = performance.now();
      const isDecimal = String(target).includes('.');

      const step = (now) => {
        const progress = Math.min((now - startTime) / duration, 1);
        const easeOutQuad = 1 - (1 - progress) * (1 - progress);
        const current = start + (target - start) * easeOutQuad;

        if (isDecimal) {
          element.textContent = current.toFixed(2);
        } else {
          element.textContent = Math.floor(current).toLocaleString();
        }

        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          element.textContent = isDecimal ? target : target.toLocaleString();
        }
      };

      requestAnimationFrame(step);
    },

    /**
     * Initialize Global Dashboard Shell (Sidebar, Topbar, Toggles)
     */
    initShell() {
      // 1. Sidebar Collapse / Expand Toggle
      const sidebar = document.getElementById('appSidebar');
      const toggleBtn = document.getElementById('sidebarToggleBtn');
      const backdrop = document.getElementById('sidebarBackdrop');

      if (toggleBtn && sidebar) {
        // Restore saved preference on desktop
        const isCollapsed = localStorage.getItem('aegis_sidebar_collapsed') === 'true';
        if (isCollapsed && window.innerWidth >= 992) {
          sidebar.classList.add('collapsed');
        }

        toggleBtn.addEventListener('click', () => {
          if (window.innerWidth < 992) {
            sidebar.classList.toggle('show');
            if (backdrop) backdrop.classList.toggle('show');
          } else {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('aegis_sidebar_collapsed', sidebar.classList.contains('collapsed'));
          }
        });
      }

      if (backdrop && sidebar) {
        backdrop.addEventListener('click', () => {
          sidebar.classList.remove('show');
          backdrop.classList.remove('show');
        });
      }

      // 2. Active Sidebar Navigation Link Highlight
      const currentPath = window.location.pathname.split('/').pop() || 'dashboard.html';
      const navLinks = document.querySelectorAll('.sidebar-nav-item .nav-link');
      navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href && (href === currentPath || (currentPath === '' && href === 'dashboard.html'))) {
          link.classList.add('active');
        } else {
          link.classList.remove('active');
        }
      });

      // 3. User Profile in Topbar
      this.syncUserProfile();

      // 4. Protection Status Master Ticker & Topbar Button
      this.syncProtectionStatus();

      // 5. Setup Protection Quick Toggle Event
      const quickToggle = document.getElementById('protectionQuickToggle');
      if (quickToggle) {
        quickToggle.addEventListener('click', async () => {
          try {
            const currentSettings = await CyberApiService.getSettings();
            const newStatus = !currentSettings.protectionEnabled;
            await CyberApiService.toggleProtection(newStatus);
            this.syncProtectionStatus();
            this.showToast(
              newStatus ? 'Network Protection re-activated! DNS sinkholing enabled.' : 'Network Protection paused! Warning: Malicious queries will resolve.',
              newStatus ? 'success' : 'warning'
            );
          } catch (err) {
            CyberUI.showToast(err.message, 'danger');
          }
        });
      }

      // 6. Handle Notifications Dropdown Actions
      const clearNotifBtn = document.getElementById('clearNotificationsBtn');
      if (clearNotifBtn) {
        clearNotifBtn.addEventListener('click', (e) => {
          e.preventDefault();
          const list = document.getElementById('notificationList');
          const badge = document.getElementById('notificationBadge');
          if (list) {
            list.innerHTML = `
              <div class="text-center py-4 text-muted" style="font-size: 0.85rem;">
                <i class="fa-solid fa-bell-slash mb-2 fa-2x" style="opacity: 0.4;"></i>
                <div>No new security alerts</div>
              </div>
            `;
          }
          if (badge) badge.style.display = 'none';
          CyberUI.showToast('All notifications cleared.', 'info');
        });
      }

      // 7. Global Logout Handler
      const logoutBtns = document.querySelectorAll('.action-logout');
      logoutBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          if (confirm('Are you sure you want to log out of AegisDNS Security Console?')) {
            CyberApiService.logout();
          }
        });
      });
    },

    /**
     * Synchronize Profile details
     */
    syncUserProfile() {
      const user = CyberApiService.getCurrentUser();
      const nameElems = document.querySelectorAll('.profile-user-name');
      const roleElems = document.querySelectorAll('.profile-user-role');
      const avatarElems = document.querySelectorAll('.profile-avatar-text');

      nameElems.forEach(el => el.textContent = user.name || 'SecOps Admin');
      roleElems.forEach(el => el.textContent = user.role || 'Security Analyst');
      avatarElems.forEach(el => el.textContent = user.avatarInitials || 'SA');
    },

    /**
     * Synchronize Protection Status visual indicators across the page
     */
    async syncProtectionStatus() {
      try {
        const settings = await CyberApiService.getSettings();
        const isProtected = settings.protectionEnabled !== false;

        const quickToggle = document.getElementById('protectionQuickToggle');
        const ticker = document.getElementById('protectionStatusTicker');
        const miniStatus = document.getElementById('sidebarProtectionStatus');
        const miniPulse = document.getElementById('sidebarProtectionPulse');

        if (quickToggle) {
          if (isProtected) {
            quickToggle.classList.remove('paused');
            quickToggle.innerHTML = `
              <span class="status-pulse pulse-safe"></span>
              <span class="toggle-label text-safe">PROTECTED</span>
            `;
            quickToggle.title = 'Click to Pause Protection';
          } else {
            quickToggle.classList.add('paused');
            quickToggle.innerHTML = `
              <span class="status-pulse pulse-suspicious"></span>
              <span class="toggle-label text-suspicious">PAUSED</span>
            `;
            quickToggle.title = 'Click to Resume Protection';
          }
        }

        if (ticker) {
          if (isProtected) {
            ticker.innerHTML = `
              <span class="status-pulse pulse-safe"></span>
              <span class="text-safe fw-semibold">PROTECTED</span>
              <span class="text-dim">|</span>
              <span class="text-muted font-mono">14ms latency</span>
              <span class="text-dim">|</span>
              <span class="text-cyan font-mono">DNS Sinkhole ACTIVE</span>
            `;
          } else {
            ticker.innerHTML = `
              <span class="status-pulse pulse-suspicious"></span>
              <span class="text-suspicious fw-semibold">PROTECTION PAUSED</span>
              <span class="text-dim">|</span>
              <span class="text-malicious">VULNERABLE</span>
            `;
          }
        }

        if (miniStatus) {
          miniStatus.textContent = isProtected ? 'SHIELD ACTIVE' : 'PROTECTION PAUSED';
          miniStatus.className = isProtected ? 'fw-bold text-safe font-mono' : 'fw-bold text-suspicious font-mono';
        }

        if (miniPulse) {
          miniPulse.className = `status-pulse ${isProtected ? 'pulse-safe' : 'pulse-suspicious'}`;
        }
      } catch (e) {
        console.error('Error synchronizing protection status:', e);
      }
    }
  };
})();

// Auto-run on DOM ready for pages that include it
document.addEventListener('DOMContentLoaded', () => {
  if (typeof CyberUI !== 'undefined') {
    CyberUI.initShell();
  }
});

// Export to window
if (typeof window !== 'undefined') {
  window.CyberUI = CyberUI;
}

