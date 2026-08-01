// Comprehensive Dictionary & Pattern Reference for Password Analysis & Diceware Passphrases

export const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', '12345678', '12345', 'qwerty', 'password1',
  '1234567', 'dragon', '123123', 'admin', 'welcome', 'sunshine', 'iloveyou',
  'princess', 'charlie', 'football', 'monkey', 'pass1234', 'master', 'shadow',
  'superman', 'baseball', 'trustno1', 'secret', 'letmein', '7777777', '111111',
  'quertyuiop', '000000', '123321', '654321', 'passcode', 'login', 'testing'
]);

export const KEYBOARD_PATTERNS = [
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  '1234567890', '0987654321',
  'qazwsxedc', 'rfvtgbyhn', 'ujmikolp',
  '1qaz2wsx3edc', 'qwer', 'asdf', 'zxcv'
];

export const SUB_MAP = {
  '@': 'a', '4': 'a',
  '3': 'e',
  '1': 'i', '!': 'i',
  '0': 'o',
  '$': 's', '5': 's',
  '7': 't', '+': 't'
};

// Diceware wordlist for generating readable, secure passphrases
export const DICEWARE_WORDS = [
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
