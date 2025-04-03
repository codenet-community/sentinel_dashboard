// Shared list of attack types for consistent display across components
export const ATTACK_TYPES = [
  'SQL Injection',
  'XSS',
  'DDOS',
  'Ransomware'
] as const;

export type AttackType = typeof ATTACK_TYPES[number];

// Function to transform unknown attack types to known types
export const transformAttackType = (attackType: string, id: string): AttackType => {
  if (!attackType || attackType.toLowerCase() === 'unknown') {
    // Deterministically choose an attack type based on the ID
    const hash = id.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
    return ATTACK_TYPES[hash % ATTACK_TYPES.length];
  }
  
  // If the attack type is already in our list, return it
  if (ATTACK_TYPES.includes(attackType as AttackType)) {
    return attackType as AttackType;
  }
  
  // For any other attack type, map it to one of our standard types
  const hash = attackType.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  return ATTACK_TYPES[hash % ATTACK_TYPES.length];
};

// Generate consistent IP addresses based on ID
export const generateConsistentIP = (id: string): string => {
  // Create a deterministic hash from the ID
  const hash = id.split('').reduce((acc, char, i) => acc + char.charCodeAt(0) * (i + 1), 0);
  
  // Generate 4 octets based on the hash
  const octet1 = Math.floor((hash % 253) + 1); // 1-254 (avoiding 0 and 255)
  const octet2 = Math.floor(((hash * 13) % 253) + 1);
  const octet3 = Math.floor(((hash * 29) % 253) + 1);
  const octet4 = Math.floor(((hash * 47) % 253) + 1);
  
  return `${octet1}.${octet2}.${octet3}.${octet4}`;
};

// List of blocked IPs (will be populated from the blockchain)
export const blockedIPs: string[] = [];

// Function to add an IP to the blocked list
export const addBlockedIP = (ip: string) => {
  if (!blockedIPs.includes(ip)) {
    blockedIPs.push(ip);
  }
}; 