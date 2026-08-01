# password-strength-analyzer
Real-time password strength analyzer, brute-force crack time estimator, and breach checker web app.

📌 Features

- ✅ Checks password length
- ✅ Detects uppercase and lowercase letters
- ✅ Detects numbers
- ✅ Detects special characters
- ✅ Calculates password strength score
- ✅ Estimates password entropy
- ✅ Identifies common or weak passwords
- ✅ Provides suggestions to improve password security
- ✅ User-friendly interface

  🌐 Frontend & Core Web Stack
1) HTML5 – For semantic web structure, form controls, and inline SVG vector icons.
2) CSS3 – For the dark glassmorphic design system (backdrop-filter), CSS variables, Grid & Flexbox layouts, dynamic glow effects, and keyframe animations.
3) Vanilla JavaScript (ES6+) – For real-time DOM manipulation, strength calculation logic, pattern matching algorithms, and UI event listeners.
4) Google Fonts API – For modern typography using Inter (UI text) and JetBrains Mono (password & hash displays).

🔒 Web APIs & Browser Security Technologies
5) Web Crypto API (window.crypto.getRandomValues) – For cryptographically secure random password and passphrase generation.
6) SubtleCrypto API (crypto.subtle.digest) – For calculating SHA-1 hashes directly inside the browser.
7) Fetch API – For making asynchronous network requests to query the breach database.

🛡️ External Security APIs & Protocols
8)  Have I Been Pwned (HIBP) Range API – For checking whether a password has appeared in known data breaches.
9)  k-Anonymity Privacy Protocol – Ensures zero-knowledge privacy by sending only the first 5 characters of a SHA-1 hash across the internet. 

🧮 Cybersecurity Algorithms & Math
10)  Bit Entropy Math (E=L⋅log2R) – For calculating mathematical information entropy.
11)  L33t-Speak & Dictionary Matcher – For detecting character substitutions (@ →→ a, 3 →→ e), keyboard walks (qwerty), and sequential patterns.
12)  Diceware Passphrase Algorithm – For generating readable, multi-word passphrases (e.g. Solar-Falcon-Harvest-Matrix).

🚀 Hosting & Tools
13)  Node.js – Used to run the local HTTP development server.
14)  Git & GitHub – For version control and source code management.
15)  GitHub Pages – For free cloud website hosting.

