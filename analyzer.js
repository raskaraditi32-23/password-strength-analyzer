import { COMMON_PASSWORDS, KEYBOARD_PATTERNS, SUB_MAP } from './dictionary.js';

export function analyzePassword(password) {
  if (!password) {
    return getEmptyState();
  }

  const length = password.length;
  
  // Character composition counts
  const composition = {
    lowercase: (password.match(/[a-z]/g) || []).length,
    uppercase: (password.match(/[A-Z]/g) || []).length,
    numbers: (password.match(/[0-9]/g) || []).length,
    symbols: (password.match(/[^a-zA-Z0-9]/g) || []).length,
    total: length
  };

  // Base Pool Size calculation
  let poolSize = 0;
  if (composition.lowercase > 0) poolSize += 26;
  if (composition.uppercase > 0) poolSize += 26;
  if (composition.numbers > 0) poolSize += 10;
  if (composition.symbols > 0) poolSize += 33;
  if (poolSize === 0) poolSize = 1;

  // Theoretical Raw Entropy (bits) = L * log2(R)
  let rawEntropy = length * Math.log2(poolSize);

  // Pattern detection & Penalty system
  const detectedPatterns = [];
  let entropyPenalty = 0;

  const lowerPwd = password.toLowerCase();

  // 1. Check exact dictionary match
  if (COMMON_PASSWORDS.has(lowerPwd)) {
    detectedPatterns.push({
      type: 'COMMON_PASSWORD',
      message: 'This is a widely used top-100 breached password.'
    });
    entropyPenalty += rawEntropy * 0.85;
  }

  // 2. Check l33t speak substitutions (e.g. P@ssw0rd)
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

  // 3. Repeated Characters
  if (/(.)\1{2,}/i.test(password)) {
    detectedPatterns.push({
      type: 'REPEATED_CHARS',
      message: 'Contains 3 or more consecutive identical characters.'
    });
    entropyPenalty += 12;
  }

  // 4. Sequential Numbers/Letters (e.g. 12345, abcde)
  if (/(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(lowerPwd)) {
    detectedPatterns.push({
      type: 'SEQUENTIAL_PATTERN',
      message: 'Contains simple sequential characters (e.g. 123, abc).'
    });
    entropyPenalty += 15;
  }

  // 5. Keyboard Patterns
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

  // 6. Year patterns (e.g., 1980-2029)
  if (/(19[5-9]\d|20[0-2]\d)/.test(password)) {
    detectedPatterns.push({
      type: 'YEAR_PATTERN',
      message: 'Contains a probable birth or current year sequence.'
    });
    entropyPenalty += 10;
  }

  // Final Effective Entropy
  const effectiveEntropy = Math.max(0, Math.round(rawEntropy - entropyPenalty));

  // Determine Strength Score (0 to 100) & Category
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

  // Rule Checklist verification
  const checklist = {
    length: length >= 12,
    hasLower: composition.lowercase > 0,
    hasUpper: composition.uppercase > 0,
    hasNumber: composition.numbers > 0,
    hasSymbol: composition.symbols > 0,
    noCommonPatterns: detectedPatterns.length === 0
  };

  // Generate Tailored Actionable Suggestions
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
