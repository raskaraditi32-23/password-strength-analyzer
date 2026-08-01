import { analyzePassword } from './analyzer.js';
import { calculateCrackTimes } from './crackTime.js';
import { generatePassword, generatePassphrase } from './generator.js';
import { checkBreachStatus } from './breachChecker.js';

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const passwordInput = document.getElementById('passwordInput');
  const toggleVisibilityBtn = document.getElementById('toggleVisibilityBtn');
  const eyeIcon = document.getElementById('eyeIcon');
  const copyInputBtn = document.getElementById('copyInputBtn');
  const charCountBadge = document.getElementById('charCountBadge');

  // Gauge & Score
  const gaugeMeter = document.getElementById('gaugeMeter');
  const scoreNum = document.getElementById('scoreNum');
  const strengthBadge = document.getElementById('strengthBadge');
  const rawEntropyVal = document.getElementById('rawEntropyVal');
  const effectiveEntropyVal = document.getElementById('effectiveEntropyVal');

  // Composition
  const segLower = document.getElementById('segLower');
  const segUpper = document.getElementById('segUpper');
  const segNumber = document.getElementById('segNumber');
  const segSymbol = document.getElementById('segSymbol');
  const cntLower = document.getElementById('cntLower');
  const cntUpper = document.getElementById('cntUpper');
  const cntNumber = document.getElementById('cntNumber');
  const cntSymbol = document.getElementById('cntSymbol');

  // Crack Time
  const crackOnlineThrottled = document.getElementById('crackOnlineThrottled');
  const crackOnlineUnthrottled = document.getElementById('crackOnlineUnthrottled');
  const crackOfflineGpu = document.getElementById('crackOfflineGpu');
  const crackSupercomputer = document.getElementById('crackSupercomputer');

  // Checklist
  const chkLength = document.getElementById('chkLength');
  const chkUpper = document.getElementById('chkUpper');
  const chkLower = document.getElementById('chkLower');
  const chkNumber = document.getElementById('chkNumber');
  const chkSymbol = document.getElementById('chkSymbol');
  const chkPattern = document.getElementById('chkPattern');

  // Suggestions
  const suggestionsList = document.getElementById('suggestionsList');

  // Generator
  const tabRandomBtn = document.getElementById('tabRandomBtn');
  const tabPassphraseBtn = document.getElementById('tabPassphraseBtn');
  const panelRandom = document.getElementById('panelRandom');
  const panelPassphrase = document.getElementById('panelPassphrase');
  const genOutputText = document.getElementById('genOutputText');
  const copyGenBtn = document.getElementById('copyGenBtn');
  const generateBtn = document.getElementById('generateBtn');

  const lengthSlider = document.getElementById('lengthSlider');
  const lengthVal = document.getElementById('lengthVal');
  const chkGenUpper = document.getElementById('chkGenUpper');
  const chkGenLower = document.getElementById('chkGenLower');
  const chkGenNumber = document.getElementById('chkGenNumber');
  const chkGenSymbol = document.getElementById('chkGenSymbol');
  const chkAvoidAmbiguous = document.getElementById('chkAvoidAmbiguous');

  const wordCountSlider = document.getElementById('wordCountSlider');
  const wordCountVal = document.getElementById('wordCountVal');
  const chkCapWords = document.getElementById('chkCapWords');
  const chkIncNumber = document.getElementById('chkIncNumber');

  // Breach Shield
  const checkBreachBtn = document.getElementById('checkBreachBtn');
  const breachStatusBox = document.getElementById('breachStatusBox');
  const breachStatusText = document.getElementById('breachStatusText');

  const toastContainer = document.getElementById('toastContainer');

  let activeTab = 'random'; // 'random' or 'passphrase'

  // --- Real-time Analyzer Handler ---
  function updateAnalysis() {
    const pwd = passwordInput.value;
    charCountBadge.textContent = `${pwd.length} chars`;

    const result = analyzePassword(pwd);
    const crackTimes = calculateCrackTimes(result.effectiveEntropy);

    // 1. Update Gauge & Score
    scoreNum.textContent = result.score;
    
    // Circumference of r=70 circle is 2 * PI * 70 ≈ 439.8
    const circumference = 440;
    const offset = circumference - (result.score / 100) * circumference;
    gaugeMeter.style.strokeDashoffset = offset;

    // Update gauge meter stroke color according to rating
    const colorMap = {
      danger: '#F43F5E',
      warning: '#F59E0B',
      info: '#06B6D4',
      success: '#8B5CF6',
      emerald: '#10B981',
      neutral: '#6B7280'
    };
    gaugeMeter.style.stroke = colorMap[result.colorClass] || colorMap.danger;

    strengthBadge.textContent = result.label;
    strengthBadge.className = `strength-badge badge-${result.colorClass}`;

    rawEntropyVal.textContent = `${result.rawEntropy} bits`;
    effectiveEntropyVal.textContent = `${result.effectiveEntropy} bits`;

    // 2. Composition Breakdown
    const total = result.composition.total || 1;
    segLower.style.width = `${(result.composition.lowercase / total) * 100}%`;
    segUpper.style.width = `${(result.composition.uppercase / total) * 100}%`;
    segNumber.style.width = `${(result.composition.numbers / total) * 100}%`;
    segSymbol.style.width = `${(result.composition.symbols / total) * 100}%`;

    cntLower.textContent = result.composition.lowercase;
    cntUpper.textContent = result.composition.uppercase;
    cntNumber.textContent = result.composition.numbers;
    cntSymbol.textContent = result.composition.symbols;

    // 3. Crack Time Matrix
    crackOnlineThrottled.textContent = crackTimes.onlineThrottled;
    crackOnlineUnthrottled.textContent = crackTimes.onlineUnthrottled;
    crackOfflineGpu.textContent = crackTimes.offlineFastGpu;
    crackSupercomputer.textContent = crackTimes.supercomputer;

    // 4. Checklist Items
    toggleCheckItem(chkLength, result.checklist.length);
    toggleCheckItem(chkUpper, result.checklist.hasUpper);
    toggleCheckItem(chkLower, result.checklist.hasLower);
    toggleCheckItem(chkNumber, result.checklist.hasNumber);
    toggleCheckItem(chkSymbol, result.checklist.hasSymbol);
    toggleCheckItem(chkPattern, result.checklist.noCommonPatterns);

    // 5. Render Suggestions
    renderSuggestions(result.suggestions);

    // Reset breach status when password changes
    breachStatusBox.style.display = 'none';
  }

  function toggleCheckItem(el, passed) {
    if (passed) el.classList.add('passed');
    else el.classList.remove('passed');
  }

  function renderSuggestions(suggestions) {
    if (!suggestions || suggestions.length === 0) {
      suggestionsList.innerHTML = `
        <div class="sugg-card medium">
          <div>
            <div class="sugg-title">Enter a password above</div>
            <div class="sugg-desc">Get tailored recommendations to strengthen your password against modern GPU brute force attacks.</div>
          </div>
        </div>
      `;
      return;
    }

    suggestionsList.innerHTML = suggestions.map(s => `
      <div class="sugg-card ${s.priority}">
        <div>
          <div class="sugg-title">${escapeHtml(s.title)}</div>
          <div class="sugg-desc">${escapeHtml(s.text)}</div>
        </div>
      </div>
    `).join('');
  }

  function escapeHtml(str) {
    return str.replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    })[m]);
  }

  // --- Password Input Listeners ---
  passwordInput.addEventListener('input', updateAnalysis);

  toggleVisibilityBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    eyeIcon.innerHTML = isPassword
      ? `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`
      : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  });

  copyInputBtn.addEventListener('click', () => {
    if (!passwordInput.value) {
      showToast('No password entered to copy.', 'warning');
      return;
    }
    navigator.clipboard.writeText(passwordInput.value);
    showToast('Password copied to clipboard!', 'success');
  });

  // --- Generator Tabs & Sliders ---
  tabRandomBtn.addEventListener('click', () => {
    activeTab = 'random';
    tabRandomBtn.classList.add('active');
    tabPassphraseBtn.classList.remove('active');
    panelRandom.style.display = 'flex';
    panelPassphrase.style.display = 'none';
  });

  tabPassphraseBtn.addEventListener('click', () => {
    activeTab = 'passphrase';
    tabPassphraseBtn.classList.add('active');
    tabRandomBtn.classList.remove('active');
    panelPassphrase.style.display = 'flex';
    panelRandom.style.display = 'none';
  });

  lengthSlider.addEventListener('input', () => {
    lengthVal.textContent = lengthSlider.value;
  });

  wordCountSlider.addEventListener('input', () => {
    wordCountVal.textContent = wordCountSlider.value;
  });

  function handleGenerate() {
    let generated = '';
    if (activeTab === 'random') {
      generated = generatePassword({
        length: parseInt(lengthSlider.value, 10),
        useLower: chkGenLower.checked,
        useUpper: chkGenUpper.checked,
        useNumbers: chkGenNumber.checked,
        useSymbols: chkGenSymbol.checked,
        avoidAmbiguous: chkAvoidAmbiguous.checked
      });
    } else {
      generated = generatePassphrase({
        wordCount: parseInt(wordCountSlider.value, 10),
        capitalize: chkCapWords.checked,
        includeNumber: chkIncNumber.checked
      });
    }

    genOutputText.textContent = generated;

    // Automatically load generated password into analyzer for instant feedback
    passwordInput.value = generated;
    updateAnalysis();
    showToast('Generated & loaded into analyzer!', 'success');
  }

  generateBtn.addEventListener('click', handleGenerate);

  copyGenBtn.addEventListener('click', () => {
    const text = genOutputText.textContent;
    if (!text || text === 'Generate a password') return;
    navigator.clipboard.writeText(text);
    showToast('Generated password copied!', 'success');
  });

  // --- Breach Checker ---
  checkBreachBtn.addEventListener('click', async () => {
    const pwd = passwordInput.value;
    if (!pwd) {
      showToast('Enter a password first to check breach status.', 'warning');
      return;
    }

    checkBreachBtn.disabled = true;
    checkBreachBtn.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>
      Auditing Hash...
    `;

    const breachResult = await checkBreachStatus(pwd);

    checkBreachBtn.disabled = false;
    checkBreachBtn.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      Check Breach Exposure
    `;

    breachStatusBox.style.display = 'flex';
    if (breachResult.pwned) {
      breachStatusBox.className = 'breach-status-box pwned';
      breachStatusText.style.color = 'var(--rose-primary)';
      breachStatusText.textContent = breachResult.message;
    } else {
      breachStatusBox.className = 'breach-status-box safe';
      breachStatusText.style.color = 'var(--emerald-primary)';
      breachStatusText.textContent = breachResult.message;
    }
  });

  // --- Toast Notifications ---
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      <span>${escapeHtml(message)}</span>
    `;

    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  // Initial trigger for generator
  handleGenerate();
});
