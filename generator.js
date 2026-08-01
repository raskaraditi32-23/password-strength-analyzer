import { DICEWARE_WORDS } from './dictionary.js';

const CHAR_SETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

const AMBIGUOUS_CHARS = /[0O1lI]/g;

export function generatePassword({
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

  // Ensure at least 1 character from each selected set is included
  const requiredChars = [];
  if (useLower) requiredChars.push(getRandomChar(CHAR_SETS.lowercase, avoidAmbiguous));
  if (useUpper) requiredChars.push(getRandomChar(CHAR_SETS.uppercase, avoidAmbiguous));
  if (useNumbers) requiredChars.push(getRandomChar(CHAR_SETS.numbers, avoidAmbiguous));
  if (useSymbols) requiredChars.push(getRandomChar(CHAR_SETS.symbols, avoidAmbiguous));

  const arrResult = result.split('');
  for (let i = 0; i < requiredChars.length && i < arrResult.length; i++) {
    arrResult[i] = requiredChars[i];
  }

  // Shuffle using Fisher-Yates and Web Crypto
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

export function generatePassphrase({
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
    const num = (numRand[0] % 90) + 10; // 2-digit number
    selectedWords.push(num.toString());
  }

  return selectedWords.join(separator);
}
