import { BlockchainData, BlockchainBlock, ThreatData } from '@/hooks/useThreatData';
import { v4 as uuidv4 } from 'uuid';

// Function to generate random date within the last 24 hours
const getRandomRecentDate = (): string => {
  const now = new Date();
  const hoursAgo = Math.floor(Math.random() * 24); // Random hours between 0-24
  const minutesAgo = Math.floor(Math.random() * 60); // Random minutes between 0-60
  const secondsAgo = Math.floor(Math.random() * 60); // Random seconds between 0-60
  
  now.setHours(now.getHours() - hoursAgo);
  now.setMinutes(now.getMinutes() - minutesAgo);
  now.setSeconds(now.getSeconds() - secondsAgo);
  
  return now.toISOString();
};

// Function to generate random IP addresses
const getRandomIP = (): string => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
};

// Function to generate random port number
const getRandomPort = (): number => {
  return Math.floor(Math.random() * 65535);
};

// Function to generate hash
const generateHash = (input: string): string => {
  let hash = '';
  const characters = 'abcdef0123456789';
  const prefix = input.slice(0, 8);
  
  for (let i = 0; i < 56; i++) {
    hash += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  
  return prefix + hash;
};

// Generate mock attack types
const attackTypes = [
  'SQL Injection',
  'XSS',
  'DDOS',
  'Brute Force',
  'Ransomware',
  'MITM',
  'Credential Stuffing',
  'Memory Corruption',
  'Supply Chain Attack',
  'Phishing Attack',
  'Directory Traversal',
  'Command Injection',
  'Remote Code Execution',
  'Server-Side Request Forgery',
  'Advanced Persistent Threat'
];

// Generate mock protocols
const protocols = ['HTTP', 'HTTPS', 'FTP', 'SMTP', 'SSH', 'Telnet', 'DNS', 'WebSocket'];

// Generate mock URL paths
const urlPaths = [
  '/admin/login',
  '/api/v1/users',
  '/login.php',
  '/wp-admin',
  '/dashboard',
  '/api/authenticate',
  '/checkout/payment',
  '/user/profile',
  '/search',
  '/upload'
];

// Generate mock user agents
const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
  'curl/7.64.1',
  'PostmanRuntime/7.28.0',
  'python-requests/2.26.0'
];

// Generate mock methods
const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];

// Generate mock severity levels
const severityLevels: Array<'High' | 'Medium' | 'Low'> = ['High', 'Medium', 'Low'];

// Generate mock status values
const statusValues = ['Active', 'Mitigated'];

// Generate mock flags
const flags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'];

// Function to generate random threat data
const generateThreatData = (): ThreatData => {
  // Bias towards medium severity most common, high severity less common
  const severityRoll = Math.random();
  let severity: 'High' | 'Medium' | 'Low';
  
  if (severityRoll < 0.2) {
    severity = 'High';
  } else if (severityRoll < 0.7) {
    severity = 'Medium';
  } else {
    severity = 'Low';
  }
  
  // Bias towards active status (70% active, 30% mitigated)
  const status = Math.random() < 0.7 ? 'Active' : 'Mitigated';
  
  return {
    id: uuidv4(),
    attack_type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
    ip: getRandomIP(),
    severity,
    status,
    timestamp: getRandomRecentDate(),
    details: {
      destination_port: getRandomPort(),
      source_port: getRandomPort(),
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      url_path: urlPaths[Math.floor(Math.random() * urlPaths.length)],
      method: methods[Math.floor(Math.random() * methods.length)],
      user_agent: userAgents[Math.floor(Math.random() * userAgents.length)],
      flag: flags[Math.floor(Math.random() * flags.length)]
    }
  };
};

// Function to generate a single blockchain block
const generateBlockchainBlock = (index: number, previousHash: string): BlockchainBlock => {
  const threatData = generateThreatData();
  const timestamp = threatData.timestamp;
  const hash = generateHash(`block${index}`);
  const dataHash = generateHash(`data${index}`);
  
  return {
    data: threatData,
    timestamp,
    hash,
    data_hash: dataHash,
    previous_hash: previousHash
  };
};

// Function to generate complete blockchain data
export const generateDemoData = (): BlockchainData => {
  const chainLength = 50 + Math.floor(Math.random() * 20); // Generate between 50-70 blocks
  const chain: BlockchainBlock[] = [];
  
  // Generate genesis block
  const genesisBlock: BlockchainBlock = {
    data: { 
      message: "Genesis Block", 
      type: "system" 
    },
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(), // 24 hours ago
    hash: generateHash('genesis'),
    data_hash: generateHash('genesisdata'),
    previous_hash: '0000000000000000000000000000000000000000000000000000000000000000'
  };
  
  chain.push(genesisBlock);
  
  // Generate the rest of the chain
  for (let i = 1; i < chainLength; i++) {
    const block = generateBlockchainBlock(i, chain[i - 1].hash);
    chain.push(block);
  }
  
  // Sort the chain by timestamp to ensure chronological order
  chain.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  return {
    chain,
    length: chain.length
  };
}; 