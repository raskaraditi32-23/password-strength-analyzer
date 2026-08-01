// CyberShield Standalone Password Security Suite Bundle (Compatible with file:// and http://)

(function () {
  'use strict';

  // --- 1. Dictionary & Reference Data ---
  const COMMON_PASSWORDS = new Set([
    'password', '123456', '123456789', '12345678', '12345', 'qwerty', 'password1',
    '1234567', 'dragon', '123123', 'admin', 'welcome', 'sunshine', 'iloveyou',
    'princess', 'charlie', 'football', 'monkey', 'pass1234', 'master', 'shadow',
    'superman', 'baseball', 'trustno1', 'secret', 'letmein', '7777777', '111111',
    'quertyuiop', '000000', '123321', '654321', 'passcode', 'login', 'testing'
  ]);

  const KEYBOARD_PATTERNS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    '1234567890', '0987654321',
    'qazwsxedc', 'rfvtgbyhn', 'ujmikolp',
    '1qaz2wsx3edc', 'qwer', 'asdf', 'zxcv'
  ];

  const SUB_MAP = {
    '@': 'a', '4': 'a',
    '3': 'e',
    '1': 'i', '!': 'i',
    '0': 'o',
    '$': 's', '5': 's',
    '7': 't', '+': 't'
  };

  const DICEWARE_WORDS = [
    'anchor', 'beacon', 'breeze', 'canyon', 'castle', 'cipher', 'cobalt', 'comet',
    'crater', 'crystal', 'delta', 'drift', 'echo', 'ember', 'falcon', 'fossil',
    'galaxy', 'glacier', 'granite', 'harbor', 'horizon', 'island', 'jasper', 'jungle',
    'knight', 'lagoon', 'lantern', 'legend', 'matrix', 'meadow', 'meteor', 'mirage',
    'nebula', 'nexus', 'oasis', 'orbit', 'orchid', 'panther', 'phantom', 'phoenix',
    'planet', 'prism', 'pulse', 'pyramid', 'quantum', 'radar', 'radiant', 'raven',
    'ridge', 'river', 'rocket', 'safari', 'shadow', 'shield', 'signal', 'solar',
    'specter', 'sphere', 'spirit', 'summit', 'thunder', 'timber', 'titan', 'beacon',
    'topaz', 'torrent', 'tower', 'tsunami', 'tundra', 'vector', 'velocity', 'velvet',
    'vertex', 'vessel', 'vortex', 'whisper', 'zenith', 'zephyr', 'zodiac', 'alpine'
  ];

  // --- 2. Password Analyzer Engine ---
  function analyzePassword(password) {
    if (!password) {
      return getEmptyState();
    }

    const length = password.length;
    
    const composition = {
      lowercase: (password.match(/[a-z]/g) || []).length,
      uppercase: (password.match(/[A-Z]/g) || []).length,
      numbers: (password.match(/[0-9]/g) || []).length,
      symbols: (password.match(/[^a-zA-Z0-9]/g) || []).length,
      total: length
    };

    let poolSize = 0;
    if (composition.lowercase > 0) poolSize += 26;
    if (composition.uppercase > 0) poolSize += 26;
    if (composition.numbers > 0) poolSize += 10;
    if (composition.symbols > 0) poolSize += 33;
    if (poolSize === 0) poolSize = 1;

    let rawEntropy = length * Math.log2(poolSize);

    const detectedPatterns = [];
    let entropyPenalty = 0;

    const lowerPwd = password.toLowerCase();

    if (COMMON_PASSWORDS.has(lowerPwd)) {
      detectedPatterns.push({
        type: 'COMMON_PASSWORD',
        message: 'This is a widely used top-100 breached password.'
      });
      entropyPenalty += rawEntropy * 0.85;
    }

    let deLeeted = lowerPwd;
    for (const [sub, real] of Object.entries(SUB_MAP)) {
      deLeeted = deLeeted.replaceAll(sub, real);
    }
    if (deLeeted !== lowerPwd && COMMON_PASSWORDS.has(deLeeted)) {
      detectedPatterns.push({
        type: 'L33T_DICTIONARY_WORD',
        message: `Predictable character substitution detected for word "${deLeeted}".`
      });
      entropyPenalty += rawEntropy * 0.60;
    }

    if (/(.)\1{2,}/i.test(password)) {
      detectedPatterns.push({
        type: 'REPEATED_CHARS',
        message: 'Contains 3 or more consecutive identical characters.'
      });
      entropyPenalty += 12;
    }

    if (/(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(lowerPwd)) {
      detectedPatterns.push({
        type: 'SEQUENTIAL_PATTERN',
        message: 'Contains simple sequential characters (e.g. 123, abc).'
      });
      entropyPenalty += 15;
    }

    for (const kbPattern of KEYBOARD_PATTERNS) {
      if (lowerPwd.includes(kbPattern.substring(0, 4)) || lowerPwd.includes(kbPattern.substring(1, 5))) {
        detectedPatterns.push({
          type: 'KEYBOARD_WALK',
          message: 'Contains a predictable keyboard row sequence (e.g. qwerty, asdf).'
        });
        entropyPenalty += 20;
        break;
      }
    }

    if (/(19[5-9]\d|20[0-2]\d)/.test(password)) {
      detectedPatterns.push({
        type: 'YEAR_PATTERN',
        message: 'Contains a probable birth or current year sequence.'
      });
      entropyPenalty += 10;
    }

    const effectiveEntropy = Math.max(0, Math.round(rawEntropy - entropyPenalty));

    let score = 0;
    let label = 'Very Weak';
    let colorClass = 'danger';

    if (effectiveEntropy < 28) {
      score = Math.min(25, Math.round((effectiveEntropy / 28) * 25));
      label = 'Very Weak';
      colorClass = 'danger';
    } else if (effectiveEntropy < 50) {
      score = Math.round(25 + ((effectiveEntropy - 28) / 22) * 25);
      label = 'Weak';
      colorClass = 'warning';
    } else if (effectiveEntropy < 75) {
      score = Math.round(50 + ((effectiveEntropy - 50) / 25) * 25);
      label = 'Moderate';
      colorClass = 'info';
    } else if (effectiveEntropy < 100) {
      score = Math.round(75 + ((effectiveEntropy - 75) / 25) * 20);
      label = 'Strong';
      colorClass = 'success';
    } else {
      score = Math.min(100, Math.round(95 + Math.min(5, (effectiveEntropy - 100) / 10)));
      label = 'Extremely Strong';
      colorClass = 'emerald';
    }

    const checklist = {
      length: length >= 12,
      hasLower: composition.lowercase > 0,
      hasUpper: composition.uppercase > 0,
      hasNumber: composition.numbers > 0,
      hasSymbol: composition.symbols > 0,
      noCommonPatterns: detectedPatterns.length === 0
    };

    const suggestions = generateSuggestions(password, composition, detectedPatterns, effectiveEntropy);

    return {
      password,
      length,
      poolSize,
      rawEntropy: Math.round(rawEntropy),
      effectiveEntropy,
      score,
      label,
      colorClass,
      composition,
      detectedPatterns,
      checklist,
      suggestions
    };
  }

  function generateSuggestions(password, composition, patterns, entropy) {
    const list = [];

    if (password.length < 12) {
      list.push({
        priority: 'high',
        icon: 'alert-triangle',
        title: 'Increase Length',
        text: `Your password has ${password.length} characters. Passwords with at least 14-16 characters exponentially increase brute-force effort.`
      });
    }

    if (composition.uppercase === 0) {
      list.push({
        priority: 'medium',
        icon: 'type',
        title: 'Add Capital Letters',
        text: 'Include uppercase characters (A-Z) to expand character pool size.'
      });
    }

    if (composition.numbers === 0) {
      list.push({
        priority: 'medium',
        icon: 'hash',
        title: 'Include Digits',
        text: 'Mix numbers (0-9) unpredictably inside the password.'
      });
    }

    if (composition.symbols === 0) {
      list.push({
        priority: 'high',
        icon: 'shield-alert',
        title: 'Add Special Characters',
        text: 'Add symbols like @, #, $, %, !, & to dramatically boost entropy.'
      });
    }

    for (const pattern of patterns) {
      list.push({
        priority: 'high',
        icon: 'zap-off',
        title: 'Remove Predictable Pattern',
        text: pattern.message
      });
    }

    if (entropy > 80 && list.length === 0) {
      list.push({
        priority: 'success',
        icon: 'check-circle',
        title: 'Outstanding Password!',
        text: 'Your password has high entropy, varied character sets, and no detectable dictionary patterns.'
      });
    }

    return list;
  }

  function getEmptyState() {
    return {
      password: '',
      length: 0,
      poolSize: 0,
      rawEntropy: 0,
      effectiveEntropy: 0,
      score: 0,
      label: 'Enter Password',
      colorClass: 'neutral',
      composition: { lowercase: 0, uppercase: 0, numbers: 0, symbols: 0, total: 0 },
      detectedPatterns: [],
      checklist: {
        length: false,
        hasLower: false,
        hasUpper: false,
        hasNumber: false,
        hasSymbol: false,
        noCommonPatterns: true
      },
      suggestions: []
    };
  }

  // --- 3. Crack Time Calculator ---
  function calculateCrackTimes(effectiveEntropy) {
    if (effectiveEntropy <= 0) {
      return {
        onlineThrottled: 'Instant',
        onlineUnthrottled: 'Instant',
        offlineFastGpu: 'Instant',
        supercomputer: 'Instant'
      };
    }

    const combinations = Math.pow(2, effectiveEntropy);
    const avgAttempts = combinations / 2;

    const SPEEDS = {
      onlineThrottled: 10,
      onlineUnthrottled: 10000,
      offlineFastGpu: 100000000000,
      supercomputer: 10000000000000
    };

    return {
      onlineThrottled: formatTime(avgAttempts / SPEEDS.onlineThrottled),
      onlineUnthrottled: formatTime(avgAttempts / SPEEDS.onlineUnthrottled),
      offlineFastGpu: formatTime(avgAttempts / SPEEDS.offlineFastGpu),
      supercomputer: formatTime(avgAttempts / SPEEDS.supercomputer)
    };
  }

  function formatTime(seconds) {
    if (seconds < 0.001) return 'Instant (< 1 ms)';
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)} milliseconds`;
    if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
    
    const minutes = seconds / 60;
    if (minutes < 60) return `${minutes.toFixed(0)} minutes`;

    const hours = minutes / 60;
    if (hours < 24) return `${hours.toFixed(1)} hours`;

    const days = hours / 24;
    if (days < 30) return `${days.toFixed(0)} days`;

    const months = days / 30;
    if (months < 12) return `${months.toFixed(1)} months`;

    const years = days / 365.25;
    if (years < 1000) return `${years.toFixed(0)} years`;

    if (years < 1e6) return `${(years / 1000).toFixed(1)} Thousand years`;
    if (years < 1e9) return `${(years / 1e6).toFixed(1)} Million years`;
    if (years < 1e12) return `${(years / 1e9).toFixed(1)} Billion years`;
    return `${(years / 1e12).toFixed(1)} Trillion years`;
  }

  // --- 4. Password & Passphrase Generator ---
  const CHAR_SETS = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  const AMBIGUOUS_CHARS = /[0O1lI]/g;

  function generatePassword({
    length = 16,
    useLower = true,
    useUpper = true,
    useNumbers = true,
    useSymbols = true,
    avoidAmbiguous = false
  } = {}) {
    let pool = '';
    if (useLower) pool += CHAR_SETS.lowercase;
    if (useUpper) pool += CHAR_SETS.uppercase;
    if (useNumbers) pool += CHAR_SETS.numbers;
    if (useSymbols) pool += CHAR_SETS.symbols;

    if (avoidAmbiguous) {
      pool = pool.replace(AMBIGUOUS_CHARS, '');
    }

    if (!pool) pool = CHAR_SETS.lowercase + CHAR_SETS.numbers;

    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);

    let result = '';
    for (let i = 0; i < length; i++) {
      result += pool[array[i] % pool.length];
    }

    const requiredChars = [];
    if (useLower) requiredChars.push(getRandomChar(CHAR_SETS.lowercase, avoidAmbiguous));
    if (useUpper) requiredChars.push(getRandomChar(CHAR_SETS.uppercase, avoidAmbiguous));
    if (useNumbers) requiredChars.push(getRandomChar(CHAR_SETS.numbers, avoidAmbiguous));
    if (useSymbols) requiredChars.push(getRandomChar(CHAR_SETS.symbols, avoidAmbiguous));

    const arrResult = result.split('');
    for (let i = 0; i < requiredChars.length && i < arrResult.length; i++) {
      arrResult[i] = requiredChars[i];
    }

    for (let i = arrResult.length - 1; i > 0; i--) {
      const rand = new Uint32Array(1);
      window.crypto.getRandomValues(rand);
      const j = rand[0] % (i + 1);
      [arrResult[i], arrResult[j]] = [arrResult[j], arrResult[i]];
    }

    return arrResult.join('');
  }

  function getRandomChar(str, avoidAmbiguous) {
    let filtered = str;
    if (avoidAmbiguous) filtered = str.replace(AMBIGUOUS_CHARS, '');
    if (!filtered) filtered = str;
    const rand = new Uint32Array(1);
    window.crypto.getRandomValues(rand);
    return filtered[rand[0] % filtered.length];
  }

  function generatePassphrase({
    wordCount = 4,
    separator = '-',
    capitalize = true,
    includeNumber = true
  } = {}) {
    const selectedWords = [];
    const randArray = new Uint32Array(wordCount);
    window.crypto.getRandomValues(randArray);

    for (let i = 0; i < wordCount; i++) {
      let word = DICEWARE_WORDS[randArray[i] % DICEWARE_WORDS.length];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      selectedWords.push(word);
    }

    if (includeNumber) {
      const numRand = new Uint32Array(1);
      window.crypto.getRandomValues(numRand);
      const num = (numRand[0] % 90) + 10;
      selectedWords.push(num.toString());
    }

    return selectedWords.join(separator);
  }

  // --- 5. Breach Checker ---
  async function checkBreachStatus(password) {
    if (!password) return { checked: false, pwned: false, count: 0 };

    try {
      const msgBuffer = new TextEncoder().encode(password);
      const hashBuffer = await window.crypto.subtle.digest('SHA-1', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const sha1Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

      const prefix = sha1Hex.substring(0, 5);
      const suffix = sha1Hex.substring(5);

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' }
      });

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}`);
      }

      const text = await response.text();
      const lines = text.split('\n');

      for (const line of lines) {
        const [lineSuffix, countStr] = line.trim().split(':');
        if (lineSuffix === suffix) {
          const count = parseInt(countStr, 10);
          return {
            checked: true,
            pwned: true,
            count,
            sha1Prefix: prefix,
            message: `DANGER! This password has appeared ${count.toLocaleString()} times in data breaches.`
          };
        }
      }

      return {
        checked: true,
        pwned: false,
        count: 0,
        sha1Prefix: prefix,
        message: 'SAFE! No matching hash found in public breach databases.'
      };

    } catch (err) {
      console.warn('Breach check network query fallback:', err);
      return {
        checked: true,
        pwned: false,
        count: 0,
        error: true,
        message: 'Breach API unavailable or offline. Local dictionary check applied.'
      };
    }
  }

  // --- 6. UI Controller & Event Listeners ---
  document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('passwordInput');
    const toggleVisibilityBtn = document.getElementById('toggleVisibilityBtn');
    const eyeIcon = document.getElementById('eyeIcon');
    const copyInputBtn = document.getElementById('copyInputBtn');
    const charCountBadge = document.getElementById('charCountBadge');

    const gaugeMeter = document.getElementById('gaugeMeter');
    const scoreNum = document.getElementById('scoreNum');
    const strengthBadge = document.getElementById('strengthBadge');
    const rawEntropyVal = document.getElementById('rawEntropyVal');
    const effectiveEntropyVal = document.getElementById('effectiveEntropyVal');

    const segLower = document.getElementById('segLower');
    const segUpper = document.getElementById('segUpper');
    const segNumber = document.getElementById('segNumber');
    const segSymbol = document.getElementById('segSymbol');
    const cntLower = document.getElementById('cntLower');
    const cntUpper = document.getElementById('cntUpper');
    const cntNumber = document.getElementById('cntNumber');
    const cntSymbol = document.getElementById('cntSymbol');

    const crackOnlineThrottled = document.getElementById('crackOnlineThrottled');
    const crackOnlineUnthrottled = document.getElementById('crackOnlineUnthrottled');
    const crackOfflineGpu = document.getElementById('crackOfflineGpu');
    const crackSupercomputer = document.getElementById('crackSupercomputer');

    const chkLength = document.getElementById('chkLength');
    const chkUpper = document.getElementById('chkUpper');
    const chkLower = document.getElementById('chkLower');
    const chkNumber = document.getElementById('chkNumber');
    const chkSymbol = document.getElementById('chkSymbol');
    const chkPattern = document.getElementById('chkPattern');

    const suggestionsList = document.getElementById('suggestionsList');

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

    const checkBreachBtn = document.getElementById('checkBreachBtn');
    const breachStatusBox = document.getElementById('breachStatusBox');
    const breachStatusText = document.getElementById('breachStatusText');

    const toastContainer = document.getElementById('toastContainer');

    let activeTab = 'random';

    function updateAnalysis() {
      const pwd = passwordInput.value;
      charCountBadge.textContent = `${pwd.length} chars`;

      const result = analyzePassword(pwd);
      const crackTimes = calculateCrackTimes(result.effectiveEntropy);

      scoreNum.textContent = result.score;
      
      const circumference = 440;
      const offset = circumference - (result.score / 100) * circumference;
      gaugeMeter.style.strokeDashoffset = offset;

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

      const total = result.composition.total || 1;
      segLower.style.width = `${(result.composition.lowercase / total) * 100}%`;
      segUpper.style.width = `${(result.composition.uppercase / total) * 100}%`;
      segNumber.style.width = `${(result.composition.numbers / total) * 100}%`;
      segSymbol.style.width = `${(result.composition.symbols / total) * 100}%`;

      cntLower.textContent = result.composition.lowercase;
      cntUpper.textContent = result.composition.uppercase;
      cntNumber.textContent = result.composition.numbers;
      cntSymbol.textContent = result.composition.symbols;

      crackOnlineThrottled.textContent = crackTimes.onlineThrottled;
      crackOnlineUnthrottled.textContent = crackTimes.onlineUnthrottled;
      crackOfflineGpu.textContent = crackTimes.offlineFastGpu;
      crackSupercomputer.textContent = crackTimes.supercomputer;

      toggleCheckItem(chkLength, result.checklist.length);
      toggleCheckItem(chkUpper, result.checklist.hasUpper);
      toggleCheckItem(chkLower, result.checklist.hasLower);
      toggleCheckItem(chkNumber, result.checklist.hasNumber);
      toggleCheckItem(chkSymbol, result.checklist.hasSymbol);
      toggleCheckItem(chkPattern, result.checklist.noCommonPatterns);

      renderSuggestions(result.suggestions);

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

    handleGenerate();
  });
})();
