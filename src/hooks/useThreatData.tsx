import { useState, useEffect, useCallback, useRef } from 'react';
import { toast } from 'sonner';
import { generateDemoData } from '@/utils/demoData';
import { AttackType } from '@/utils/attackTypes';
import { initializeApp } from 'firebase/app';
import { getDatabase, ref, onValue } from 'firebase/database';

export interface ThreatDetail {
  url_path: string;
  protocol?: string;
  destination_port?: number;
  source_port?: number;
  user_agent?: string;
  method?: string;
  flag?: string;
}

export interface ThreatData {
  attack_type: string;
  details: ThreatDetail;
  id: string;
  ip: string;
  severity: 'High' | 'Medium' | 'Low';
  status: string;
  timestamp: string;
}

export interface BlockchainBlock {
  data: ThreatData | { message: string; type: string };
  data_hash: string;
  hash: string;
  previous_hash: string;
  timestamp: string;
}

export interface BlockchainData {
  chain: BlockchainBlock[];
  length: number;
}

export interface ThreatLedger {
  [key: string]: {
    timestamp: string;
    analysisId: string;
    totalThreats: number;
    threatTypes: Record<string, number>;
    threats: ThreatData[];
    stats: {
      totalEntries: number;
      threatCount: number;
      normalCount: number;
      attackTypes: Record<string, number>;
      protocols: Record<string, number>;
      services: Record<string, number>;
    };
  }
}

interface useThreatDataProps {
  apiKey?: string;
  apiUrl?: string;
  blockchainUrl?: string;
}

const useThreatData = (settings: useThreatDataProps) => {
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [threatData, setThreatData] = useState<ThreatData[]>([]);
  const [blockchainData, setBlockchainData] = useState<BlockchainData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [lastSuccessfulFetch, setLastSuccessfulFetch] = useState<Date | null>(null);
  
  const [blockchainConnected, setBlockchainConnected] = useState(false);
  const [apiConnected, setApiConnected] = useState(false);
  const [usingFallbackData, setUsingFallbackData] = useState(false);
  const [bankaiMode, setBankaiMode] = useState(false);
  
  // Firebase state
  const [firebaseConnected, setFirebaseConnected] = useState(false);
  const [threatLedger, setThreatLedger] = useState<ThreatLedger | null>(null);
  const firebaseAppRef = useRef<any>(null);
  const firebaseDatabaseRef = useRef<any>(null);
  
  const { blockchainUrl, apiUrl } = settings;
  
  const intervalRef = useRef<number | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const seenThreatIdsRef = useRef<Set<string>>(new Set());
  const previousThreatDataRef = useRef<ThreatData[]>([]);
  const demoDataRef = useRef<{ data: BlockchainData, lastUpdated: number } | null>(null);

  const isDemoMode = useCallback(() => {
    return blockchainUrl?.includes('demo.api.sentinel') || apiUrl?.includes('demo.api.sentinel');
  }, [blockchainUrl, apiUrl]);

  const processBlockchainData = (data: BlockchainData): ThreatData[] => {
    if (bankaiMode) {
      // In Bankai mode, show exactly what's in the blockchain without altering it
      return data.chain
        .filter(block => 'attack_type' in block.data)
        .map(block => block.data as ThreatData);
    } else {
      // In regular mode, maintain the original behavior which may alter data
      return data.chain
        .filter(block => 'attack_type' in block.data)
        .map(block => {
          const data = block.data as ThreatData;
          // If data has unknown attack type or missing IP, we may want to handle it
          // but in Bankai mode we just return the raw data
          if (data.attack_type.toLowerCase() === 'unknown' || !data.ip) {
            const modifiedData = { ...data };
            // Handle missing data if needed
            if (!modifiedData.ip) {
              modifiedData.ip = 'unknown';
            }
            return modifiedData;
          }
          return data;
        });
    }
  };

  const getDemoData = useCallback(() => {
    const now = Date.now();
    
    if (!demoDataRef.current || (now - demoDataRef.current.lastUpdated > 30000)) {
      demoDataRef.current = {
        data: generateDemoData(),
        lastUpdated: now
      };
    }
    
    return demoDataRef.current.data;
  }, []);

  // Firebase configuration - using the credentials specified elsewhere in the app
  const firebaseConfig = {
    apiKey: "AIzaSyBSbonwVE3PPXIIrSrvrB75u2AQ_B_Tni4",
    authDomain: "discraft-c1c41.firebaseapp.com",
    databaseURL: "https://discraft-c1c41-default-rtdb.firebaseio.com",
    projectId: "discraft-c1c41",
    storageBucket: "discraft-c1c41.appspot.com",
    messagingSenderId: "525620150766",
    appId: "1:525620150766:web:a426e68d206c68764aceff"
  };

  const connectToFirebase = useCallback(async () => {
    console.log('🔥 useThreatData: Attempting to connect to Firebase...');
    setIsLoading(true);
    setError(null);
    setConnectionError(null);
    
    try {
      if (!firebaseAppRef.current) {
        console.log('🔥 useThreatData: No existing Firebase app found, initializing new connection');
        
        try {
          // Initialize Firebase
          console.log('🔥 useThreatData: Initializing Firebase app...');
          firebaseAppRef.current = initializeApp(firebaseConfig);
          console.log('🔥 useThreatData: Firebase app initialized successfully:', firebaseAppRef.current.name);
        } catch (initError) {
          console.error('🔥 useThreatData: Error initializing Firebase app:', initError);
          throw new Error(`Firebase initialization failed: ${(initError as Error).message}`);
        }
        
        try {
          // Get a reference to the database service
          console.log('🔥 useThreatData: Getting database reference...');
          firebaseDatabaseRef.current = getDatabase(firebaseAppRef.current);
          console.log('🔥 useThreatData: Database reference obtained successfully');
        } catch (dbError) {
          console.error('🔥 useThreatData: Error getting database reference:', dbError);
          throw new Error(`Database connection failed: ${(dbError as Error).message}`);
        }
        
        // Set up listener for threat ledger data
        try {
          console.log('🔥 useThreatData: Setting up threat ledger listener');
          const threatLedgerRef = ref(firebaseDatabaseRef.current, 'threatLedger');
          onValue(threatLedgerRef, (snapshot) => {
            console.log('🔥 useThreatData: Received threat ledger snapshot');
            const data = snapshot.val() as ThreatLedger;
            if (data) {
              console.log('🔥 useThreatData: Processing threat ledger data', Object.keys(data).length, 'entries');
              setThreatLedger(data);
              
              // Convert the first ledger entry's threats to our ThreatData format
              const firstEntryKey = Object.keys(data)[0];
              if (firstEntryKey && data[firstEntryKey]?.threats) {
                const threats = data[firstEntryKey].threats.map(threat => {
                  // Ensure timestamp is valid
                  let validTimestamp = threat.timestamp;
                  try {
                    // Check if timestamp is valid, if not use current time
                    const date = new Date(threat.timestamp);
                    if (isNaN(date.getTime())) {
                      console.warn('Invalid timestamp detected:', threat.timestamp);
                      validTimestamp = new Date().toISOString();
                    }
                  } catch (error) {
                    console.error('Error parsing timestamp:', threat.timestamp, error);
                    validTimestamp = new Date().toISOString();
                  }
                  
                  return {
                    attack_type: threat.attackType,
                    details: {
                      url_path: threat.info,
                      protocol: threat.protocol,
                    },
                    id: `${threat.sourceIP}-${validTimestamp}`,
                    ip: threat.sourceIP,
                    severity: threat.severity,
                    status: threat.isThreat ? "Active" : "Mitigated",
                    timestamp: validTimestamp
                  };
                });
                
                setThreatData(threats);
                
                // Create a blockchain-like structure for backward compatibility
                const chainBlocks = threats.map(threat => ({
                  data: threat,
                  data_hash: Math.random().toString(36).substr(2, 9),
                  hash: Math.random().toString(36).substr(2, 9),
                  previous_hash: Math.random().toString(36).substr(2, 9),
                  timestamp: new Date().toISOString()
                }));
                
                setBlockchainData({
                  chain: chainBlocks,
                  length: chainBlocks.length
                });
              }
              
              setLastUpdated(new Date());
              setLastSuccessfulFetch(new Date());
              setIsConnected(true);
              setFirebaseConnected(true);
              setBlockchainConnected(true); // For backward compatibility
              setApiConnected(true); // For backward compatibility
              
              toast.success('Connected to Firebase threat data');
            }
          }, (error) => {
            console.error('🔥 useThreatData: Threat ledger data retrieval error:', error);
            setError(`Firebase error: ${error.message}`);
            setConnectionError(`Failed to retrieve threat data: ${error.message}`);
            setIsConnected(false);
            setFirebaseConnected(false);
            throw new Error(`Firebase data error: ${error.message}`);
          });
        } catch (threatLedgerError) {
          console.error('🔥 useThreatData: Failed to set up threat ledger:', threatLedgerError);
          throw new Error('Could not access threat ledger');
        }
      }
      
      return { success: true };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Connection failed';
      setConnectionError(errorMessage);
      setError(errorMessage);
      setIsConnected(false);
      setFirebaseConnected(false);
      setBlockchainConnected(false);
      setApiConnected(false);
      toast.error(`Failed to connect to Firebase: ${errorMessage}`);
      return { success: false };
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Replace the original fetchBlockchainData with one that gets data from Firebase
  const fetchBlockchainData = useCallback(async () => {
    if (!firebaseConnected) {
      // If we're not connected to Firebase yet, try connecting
      return connectToFirebase();
    } else {
      // We're already connected and the onValue listener will update the data
      return { success: true };
    }
  }, [firebaseConnected, connectToFirebase]);

  // Add the missing scheduleReconnect function
  const scheduleReconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      window.clearTimeout(reconnectTimeoutRef.current);
    }
    
    const delay = Math.min(Math.pow(2, reconnectAttempts) * 1000, 30000);
    
    reconnectTimeoutRef.current = window.setTimeout(() => {
      setReconnectAttempts(prev => prev + 1);
      connectToFirebase();
    }, delay);
  }, [reconnectAttempts, connectToFirebase]);

  // For backwards compatibility, maintain this function but make it use Firebase
  const connectToSources = useCallback(async () => {
    return connectToFirebase();
  }, [connectToFirebase]);

  // For backwards compatibility, maintain this function but make it close Firebase
  const disconnect = useCallback(() => {
    if (intervalRef.current) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    
    if (reconnectTimeoutRef.current) {
      window.clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    setIsConnected(false);
    setBlockchainConnected(false);
    setFirebaseConnected(false);
    setApiConnected(false);
    setIsReconnecting(false);
    setReconnectAttempts(0);
    toast.info('Disconnected from Firebase');
  }, []);

  // Connect to Firebase on component mount
  useEffect(() => {
    if (!isConnected && !isLoading && !isReconnecting) {
      console.log('Automatically connecting to Firebase in useThreatData');
      connectToFirebase();
    }
    
    return () => {
      if (intervalRef.current) window.clearInterval(intervalRef.current);
      if (reconnectTimeoutRef.current) window.clearTimeout(reconnectTimeoutRef.current);
      if (abortControllerRef.current) abortControllerRef.current.abort();
    };
  }, []);

  useEffect(() => {
    const staleDataCheck = setInterval(() => {
      if (isConnected && lastSuccessfulFetch) {
        const timeSinceLastFetch = Date.now() - lastSuccessfulFetch.getTime();
        if (timeSinceLastFetch > 15000 && !isReconnecting) {
          setIsReconnecting(true);
          scheduleReconnect();
        }
      }
    }, 5000);
    
    return () => clearInterval(staleDataCheck);
  }, [isConnected, lastSuccessfulFetch, isReconnecting, scheduleReconnect]);

  const threatStats = {
    total: threatData.length,
    high: threatData.filter(t => t.severity === 'High').length,
    medium: threatData.filter(t => t.severity === 'Medium').length,
    low: threatData.filter(t => t.severity === 'Low').length,
    mitigated: threatData.filter(t => t.status === 'Mitigated').length,
    active: threatData.filter(t => t.status !== 'Mitigated').length,
  };

  return {
    isConnected,
    isLoading,
    error,
    connectionError,
    lastUpdated,
    threatData,
    blockchainData,
    threatStats,
    reconnectAttempts,
    isReconnecting,
    usingFallbackData,
    blockchainConnected: firebaseConnected, // Use Firebase connection status
    apiConnected: firebaseConnected, // Use Firebase connection status
    firebaseConnected,
    threatLedger,
    connectToSources,
    disconnect,
    fetchBlockchainData,
    connectToFirebase,
    bankaiMode,
    setBankaiMode
  };
};

export { useThreatData };
export default useThreatData;