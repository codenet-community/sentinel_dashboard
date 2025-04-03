
/**
 * Utility functions for working with threat data
 */
import { ThreatData } from '@/hooks/useThreatData';

/**
 * Checks if two arrays of threat data have meaningful differences
 * @param oldThreats Previous threat data array
 * @param newThreats New threat data array
 * @returns true if data has changed in a meaningful way, false otherwise
 */
export function hasThreatsChanged(oldThreats: ThreatData[], newThreats: ThreatData[]): boolean {
  // Fast path: different lengths means definitely changed
  if (oldThreats.length !== newThreats.length) return true;
  
  // Check if all IDs match using Sets for quick lookup
  const oldIds = new Set(oldThreats.map(t => t.id));
  const newIds = new Set(newThreats.map(t => t.id));
  
  // If any new IDs appeared, data changed
  for (const id of newIds) {
    if (!oldIds.has(id)) return true;
  }
  
  // If any IDs disappeared, data changed
  for (const id of oldIds) {
    if (!newIds.has(id)) return true;
  }
  
  // Check for changes in status and other important fields
  for (const newThreat of newThreats) {
    const oldThreat = oldThreats.find(t => t.id === newThreat.id);
    if (oldThreat) {
      // Check if status or severity changed
      if (oldThreat.status !== newThreat.status || 
          oldThreat.severity !== newThreat.severity) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Filters high severity threats that haven't been mitigated
 * @param threats Array of threats
 * @param alertHistory Array of already alerted threat IDs
 * @returns Array of high severity threats that haven't been alerted yet
 */
export function getNewHighSeverityThreats(threats: ThreatData[], alertHistory: string[]): ThreatData[] {
  return threats.filter(threat => 
    threat.severity === 'High' && 
    threat.status !== 'Mitigated' && 
    !alertHistory.includes(threat.id)
  );
}

/**
 * Validates a URL string
 * @param url The URL to validate
 * @returns true if valid, false otherwise
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}
