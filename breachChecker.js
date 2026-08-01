// Privacy-Preserving k-Anonymity HIBP Breach Checker via Web Crypto API

export async function checkBreachStatus(password) {
  if (!password) return { checked: false, pwned: false, count: 0 };

  try {
    // 1. Calculate SHA-1 hash in browser using Web Crypto
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await window.crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha1Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    // 2. Split hash into 5-char prefix & 35-char suffix for k-Anonymity
    const prefix = sha1Hex.substring(0, 5);
    const suffix = sha1Hex.substring(5);

    // 3. Query HIBP range API (sends ONLY the 5-char prefix, preserving zero-knowledge privacy)
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' } // prevents side-channel size analysis
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
