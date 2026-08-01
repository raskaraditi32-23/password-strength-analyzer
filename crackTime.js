// Calculates estimated brute force time across different attack scenarios

export function calculateCrackTimes(effectiveEntropy) {
  if (effectiveEntropy <= 0) {
    return {
      onlineThrottled: 'Instant',
      onlineUnthrottled: 'Instant',
      offlineFastGpu: 'Instant',
      supercomputer: 'Instant'
    };
  }

  // Total possible combinations = 2^entropy
  const combinations = Math.pow(2, effectiveEntropy);
  // Average attempts required (50% of key space search)
  const avgAttempts = combinations / 2;

  // Guesses per second benchmarks
  const SPEEDS = {
    onlineThrottled: 10,                 // 10 attempts/sec
    onlineUnthrottled: 10000,            // 10k attempts/sec
    offlineFastGpu: 100000000000,        // 100 Billion attempts/sec (Modern multi-GPU rig)
    supercomputer: 10000000000000       // 10 Trillion attempts/sec (Quantum/Supercomputer array)
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
