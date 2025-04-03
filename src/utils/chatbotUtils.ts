import { BlockchainData, ThreatData } from '@/hooks/useThreatData';
import { ATTACK_TYPES, transformAttackType, generateConsistentIP, addBlockedIP } from './attackTypes';

/**
 * Extracts ThreatData from BlockchainData
 */
export const extractThreatData = (blockchainData: BlockchainData | null): ThreatData[] => {
  if (!blockchainData || !blockchainData.chain) return [];
  
  return blockchainData.chain
    .filter(block => 
      block.data && 
      typeof block.data === 'object' && 
      'attack_type' in block.data
    )
    .map(block => {
      const data = block.data as ThreatData;
      const transformedAttackType = transformAttackType(data.attack_type, data.id);
      
      // Generate consistent IP if it's an unknown attack type
      let ip = data.ip;
      if (data.attack_type.toLowerCase() === 'unknown' || !data.ip) {
        ip = generateConsistentIP(data.id);
        // Add this IP to blocked IPs list
        addBlockedIP(ip);
      }
      
      return {
        ...data,
        attack_type: transformedAttackType,
        ip
      };
    });
};

/**
 * Analyzes attack type patterns
 */
export const analyzeAttackPatterns = (threatData: ThreatData[]) => {
  const attackTypeCounts: Record<string, number> = {};
  
  threatData.forEach(threat => {
    attackTypeCounts[threat.attack_type] = (attackTypeCounts[threat.attack_type] || 0) + 1;
  });
  
  return Object.entries(attackTypeCounts)
    .sort(([, countA], [, countB]) => countB - countA);
};

/**
 * Analyzes protocol usage patterns
 */
export const analyzeProtocolUsage = (threatData: ThreatData[]) => {
  const protocolCounts: Record<string, number> = {};
  
  threatData.forEach(threat => {
    if (threat.details && threat.details.protocol) {
      protocolCounts[threat.details.protocol] = (protocolCounts[threat.details.protocol] || 0) + 1;
    }
  });
  
  return Object.entries(protocolCounts)
    .sort(([, countA], [, countB]) => countB - countA);
};

/**
 * Analyzes port targeting patterns
 */
export const analyzePortTargets = (threatData: ThreatData[]) => {
  const portCounts: Record<number, number> = {};
  
  threatData.forEach(threat => {
    if (threat.details && threat.details.destination_port) {
      const port = threat.details.destination_port;
      portCounts[port] = (portCounts[port] || 0) + 1;
    }
  });
  
  return Object.entries(portCounts)
    .sort(([, countA], [, countB]) => countB - countA)
    .map(([port, count]) => [parseInt(port), count]);
};

/**
 * Generates a summary of threat data
 */
export const generateThreatSummary = (threatData: ThreatData[]) => {
  if (!threatData.length) return null;
  
  const total = threatData.length;
  const highSeverity = threatData.filter(t => t.severity === 'High').length;
  const mediumSeverity = threatData.filter(t => t.severity === 'Medium').length;
  const lowSeverity = threatData.filter(t => t.severity === 'Low').length;
  
  // Count unique IPs
  const uniqueIPs = new Set(threatData.map(t => t.ip)).size;
  
  // Get latest attack
  const latestThreat = threatData[threatData.length - 1];
  
  return {
    total,
    highSeverity,
    mediumSeverity,
    lowSeverity,
    uniqueIPs,
    latestThreat
  };
};

/**
 * Gets detailed threat information for specific attack types
 */
export const getThreatDetailsByAttackType = (threatData: ThreatData[], attackType: string): ThreatData[] => {
  return threatData.filter(threat => 
    threat.attack_type.toLowerCase().includes(attackType.toLowerCase())
  );
};

/**
 * Analyzes severity trends over time
 */
export const analyzeSeverityTrends = (threatData: ThreatData[]) => {
  // Sort threats by timestamp
  const sortedThreats = [...threatData].sort((a, b) => 
    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  
  // Group threats by time period (days)
  const threatsByDay: Record<string, { high: number, medium: number, low: number }> = {};
  
  sortedThreats.forEach(threat => {
    const date = new Date(threat.timestamp);
    const day = `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`;
    
    if (!threatsByDay[day]) {
      threatsByDay[day] = { high: 0, medium: 0, low: 0 };
    }
    
    if (threat.severity === 'High') threatsByDay[day].high++;
    else if (threat.severity === 'Medium') threatsByDay[day].medium++;
    else if (threat.severity === 'Low') threatsByDay[day].low++;
  });
  
  return Object.entries(threatsByDay).map(([day, counts]) => ({
    day,
    ...counts
  }));
};

/**
 * Provides threat mitigation suggestions based on attack types
 */
export const getThreatMitigationSuggestions = (attackType: string): string[] => {
  const transformedType = transformAttackType(attackType, attackType);
  const mitigations: Record<string, string[]> = {
    'sql injection': [
      'Use parameterized queries instead of concatenating strings',
      'Implement proper input validation and sanitization',
      'Apply the principle of least privilege to database accounts',
      'Enable prepared statements in your database connections'
    ],
    'xss': [
      'Implement Content Security Policy (CSP)',
      'Encode all user-generated content before displaying it',
      'Use frameworks that automatically escape output',
      'Validate all user input on both client and server sides'
    ],
    'ddos': [
      'Implement rate limiting and request throttling',
      'Use a CDN to absorb traffic',
      'Scale infrastructure automatically during attacks',
      'Deploy DDoS protection services like Cloudflare'
    ],
    'ransomware': [
      'Maintain regular and offline backups',
      'Implement application whitelisting',
      'Use email filtering and security awareness training',
      'Segment networks to prevent lateral movement'
    ]
  };
  
  return mitigations[transformedType.toLowerCase()] || [
    'Keep all systems and applications updated with security patches',
    'Implement strong access controls and authentication mechanisms',
    'Monitor logs and network traffic for suspicious activity',
    'Conduct regular security audits and penetration testing'
  ];
};

/**
 * Generates advanced security insights from threat data
 */
export const generateSecurityInsights = (threatData: ThreatData[]) => {
  if (!threatData.length) return [];
  
  const insights: string[] = [];
  
  // Analyze attack patterns
  const attackPatterns = analyzeAttackPatterns(threatData);
  if (attackPatterns.length > 0) {
    const mostCommonAttack = attackPatterns[0][0] as string;
    const attackCount = attackPatterns[0][1] as number;
    const percentage = Math.round((attackCount / threatData.length) * 100);
    
    insights.push(`${mostCommonAttack} attacks make up ${percentage}% of all detected threats.`);
    
    // Add mitigation suggestions
    const mitigations = getThreatMitigationSuggestions(mostCommonAttack);
    insights.push(`To protect against ${mostCommonAttack}, consider: ${mitigations[0]}`);
  }
  
  // Analyze severity distribution
  const highSeverity = threatData.filter(t => t.severity === 'High').length;
  const highPercentage = Math.round((highSeverity / threatData.length) * 100);
  
  if (highPercentage > 30) {
    insights.push(`Warning: ${highPercentage}% of threats are high severity, indicating targeted attacks.`);
  }
  
  // Analyze source IPs
  const uniqueIPs = new Set(threatData.map(t => t.ip)).size;
  if (uniqueIPs === 1 && threatData.length > 3) {
    insights.push(`Multiple attacks detected from a single IP address, suggesting a concentrated attack.`);
  } else if (uniqueIPs > 10) {
    insights.push(`Attacks originating from ${uniqueIPs} different IP addresses, suggesting a distributed attack.`);
  }
  
  // Analyze port targeting
  const portTargets = analyzePortTargets(threatData);
  if (portTargets.length > 0) {
    const [topPort, count] = portTargets[0];
    insights.push(`Port ${topPort} is the most targeted, with ${count} attack attempts.`);
  }
  
  return insights;
};

/**
 * Enriches blockchain data with additional analysis
 */
export const enrichThreatData = (blockchainData: BlockchainData | null) => {
  const threatData = extractThreatData(blockchainData);
  if (!threatData.length) return null;
  
  return {
    rawData: threatData,
    summary: generateThreatSummary(threatData),
    attackPatterns: analyzeAttackPatterns(threatData).slice(0, 5),
    protocolUsage: analyzeProtocolUsage(threatData).slice(0, 5),
    portTargets: analyzePortTargets(threatData).slice(0, 5),
    severityTrends: analyzeSeverityTrends(threatData),
    insights: generateSecurityInsights(threatData)
  };
}; 