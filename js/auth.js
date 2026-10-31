/**
 * DNS-Based Malicious Domain Blocking and Network Protection System
 * Authentication & Form Validation Module
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Password Visibility Toggle (Show/Hide Password)
  const passwordToggles = document.querySelectorAll('.toggle-password-btn');
  passwordToggles.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (input) {
        const isPassword = input.getAttribute('type') === 'password';
        input.setAttribute('type', isPassword ? 'text' : 'password');
        const icon = btn.querySelector('i');
        if (icon) {
          icon.className = isPassword ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
        }
      }
    });
  });

  // 2. Password Strength Meter (Registration Page)
  const regPassword = document.getElementById('regPassword');
  const strengthFill = document.getElementById('passwordStrengthFill');
  const strengthText = document.getElementById('passwordStrengthText');

  if (regPassword && strengthFill) {
    regPassword.addEventListener('input', () => {
      const val = regPassword.value;
      let score = 0;
      if (val.length >= 8) score += 25;
      if (/[A-Z]/.test(val)) score += 25;
      if (/[0-9]/.test(val)) score += 25;
      if (/[^A-Za-z0-9]/.test(val)) score += 25;

      strengthFill.style.width = score + '%';

      if (score === 0) {
        strengthFill.style.backgroundColor = 'transparent';
        if (strengthText) strengthText.textContent = 'Enter at least 8 characters';
      } else if (score <= 25) {
        strengthFill.style.backgroundColor = '#ff3366';
        if (strengthText) strengthText.innerHTML = '<span class="text-malicious">Weak (Add uppercase & symbols)</span>';
      } else if (score <= 50) {
        strengthFill.style.backgroundColor = '#f59e0b';
        if (strengthText) strengthText.innerHTML = '<span class="text-suspicious">Fair (Add numbers & symbols)</span>';
      } else if (score <= 75) {
        strengthFill.style.backgroundColor = '#00f0ff';
        if (strengthText) strengthText.innerHTML = '<span class="text-cyan">Good Security</span>';
      } else {
        strengthFill.style.backgroundColor = '#10b981';
        if (strengthText) strengthText.innerHTML = '<span class="text-safe">Strong Cyber Defense</span>';
      }
    });
  }

  // 3. Login Form Submission & Validation
  const loginForm = document.getElementById('loginForm');
  const loginAlert = document.getElementById('loginAlert');
  const loginSubmitBtn = document.getElementById('loginSubmitBtn');

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const identifier = document.getElementById('loginIdentifier').value.trim();
      const password = document.getElementById('loginPassword').value;
      const remember = document.getElementById('loginRemember')?.checked || false;

      // Validation
      if (!identifier) {
        showAuthAlert(loginAlert, 'Please enter your username or registered email.');
        return;
      }
      if (!password) {
        showAuthAlert(loginAlert, 'Please enter your account password.');
        return;
      }

      setBtnLoading(loginSubmitBtn, true, 'Authenticating credentials...');
      hideAuthAlert(loginAlert);

      try {
        await CyberApiService.login(identifier, password, remember);
        CyberUI.showToast('Authentication verified. Welcome to AegisDNS Security Console!', 'success');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 600);
      } catch (err) {
        setBtnLoading(loginSubmitBtn, false, 'Sign In to Console <i class="fa-solid fa-arrow-right ms-1"></i>');
        showAuthAlert(loginAlert, err.message);
      }
    });
  }

  // Quick Demo Autofill Button on Login
  const demoFillBtn = document.getElementById('btnDemoCredentials');
  if (demoFillBtn) {
    demoFillBtn.addEventListener('click', () => {
      const idInput = document.getElementById('loginIdentifier');
      const passInput = document.getElementById('loginPassword');
      if (idInput && passInput) {
        idInput.value = 'admin@aegisdns.security';
        passInput.value = 'CyberShield#2026!';
        CyberUI.showToast('SecOps Admin demo credentials loaded.', 'info');
      }
    });
  }

  // 4. Registration Form Submission & Validation
  const registerForm = document.getElementById('registerForm');
  const regAlert = document.getElementById('regAlert');
  const regSubmitBtn = document.getElementById('regSubmitBtn');

  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const fullName = document.getElementById('regFullName').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      const username = document.getElementById('regUsername').value.trim();
      const password = document.getElementById('regPassword').value;
      const confirmPassword = document.getElementById('regConfirmPassword').value;
      const termsAccepted = document.getElementById('regTerms')?.checked;

      // Comprehensive Frontend Form Validation
      if (!fullName) {
        showAuthAlert(regAlert, 'Please enter your full name.');
        return;
      }
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showAuthAlert(regAlert, 'Please enter a valid business or security analyst email address.');
        return;
      }
      if (!username || username.length < 3) {
        showAuthAlert(regAlert, 'Username must be at least 3 alphanumeric characters.');
        return;
      }
      if (!password || password.length < 8) {
        showAuthAlert(regAlert, 'Password must be at least 8 characters with letters and symbols.');
        return;
      }
      if (password !== confirmPassword) {
        showAuthAlert(regAlert, 'Passwords do not match. Please verify your confirmation password.');
        return;
      }
      if (!termsAccepted) {
        showAuthAlert(regAlert, 'Please accept the Security Policy & Terms of Protection.');
        return;
      }

      setBtnLoading(regSubmitBtn, true, 'Creating SecOps Profile...');
      hideAuthAlert(regAlert);

      try {
        await CyberApiService.register({ fullName, email, username, password, confirmPassword });
        CyberUI.showToast('Account registered successfully! Redirecting to Dashboard...', 'success');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 800);
      } catch (err) {
        setBtnLoading(regSubmitBtn, false, 'Complete Registration <i class="fa-solid fa-user-shield ms-1"></i>');
        showAuthAlert(regAlert, err.message);
      }
    });
  }

  // Helper UI routines
  function showAuthAlert(alertEl, msg) {
    if (!alertEl) return;
    alertEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation me-2"></i> ${msg}`;
    alertEl.style.display = 'block';
  }

  function hideAuthAlert(alertEl) {
    if (!alertEl) return;
    alertEl.style.display = 'none';
  }

  function setBtnLoading(btn, isLoading, text) {
    if (!btn) return;
    btn.disabled = isLoading;
    if (isLoading) {
      btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin me-2"></i> ${text}`;
    } else {
      btn.innerHTML = text;
    }
  }
});

