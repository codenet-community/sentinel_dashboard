import { useState, useEffect, useRef, useCallback } from 'react';
import Header from '@/components/Header';
import ThreatStats from '@/features/stats/ThreatStats';
import LiveAttackFeed from '@/features/feeds/LiveAttackFeed';
import ThreatMap from '@/components/maps/ThreatMap';
import BlockchainViewer from '@/features/blockchain/BlockchainViewer';
import ThreatChart from '@/components/charts/ThreatChart';
import AlertBanner from '@/components/alerts/AlertBanner';
import ThreatTrends from '@/components/charts/ThreatTrends';
import BlockedIPs from '@/components/BlockedIPs';
import ConnectionStatus from '@/features/settings/ConnectionStatus';
import { useThreatData, ThreatData } from '@/hooks/useThreatData';
import { ThemeProvider } from '@/components/theme-provider';
import { Shield, AlertOctagon, Settings } from 'lucide-react';
import { getFromStorage, saveToStorage } from '@/utils/storageUtils';
import { playAudio, initializeAudio } from '@/utils/audioUtils';
import { getNewHighSeverityThreats } from '@/utils/dataUtils';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';

// Create and add alert.mp3 to public folder
const ALERT_SOUND_URL = '/alert.mp3';

const Index = () => {
  const navigate = useNavigate();
  const settingsTriggerRef = useRef<HTMLButtonElement>(null);
  
  // Load persisted settings from localStorage with error handling
  const [persistedSettings, setPersistedSettings] = useState(() => 
    getFromStorage('sentinel-connection-settings', {
      apiKey: '',
      apiUrl: '',
      blockchainUrl: '',
    })
  );
  
  // Fix the type error - converting string to boolean properly
  const [soundEnabled, setSoundEnabled] = useState(() => 
    getFromStorage('sentinel-sound-enabled', 'false') === 'true'
  );
  
  const [notificationsEnabled, setNotificationsEnabled] = useState(() => 
    getFromStorage('sentinel-notifications-enabled', 'true') === 'true'
  );
  
  const [soundVolume, setSoundVolume] = useState(() => {
    const volume = getFromStorage('sentinel-sound-volume', '70');
    return parseInt(volume, 10);
  });
  
  const [currentAlert, setCurrentAlert] = useState<ThreatData | null>(null);
  const [alertHistory, setAlertHistory] = useState<string[]>([]);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [audioLoaded, setAudioLoaded] = useState(false);
  const [audioError, setAudioError] = useState<string | null>(null);
  
  // Safely persist settings to localStorage
  const safelyPersistToStorage = useCallback((key: string, value: any) => {
    saveToStorage(key, value);
  }, []);
  
  // Store settings in localStorage when they change
  useEffect(() => {
    safelyPersistToStorage('sentinel-connection-settings', persistedSettings);
  }, [persistedSettings, safelyPersistToStorage]);
  
  useEffect(() => {
    safelyPersistToStorage('sentinel-sound-enabled', soundEnabled.toString());
  }, [soundEnabled, safelyPersistToStorage]);
  
  useEffect(() => {
    safelyPersistToStorage('sentinel-notifications-enabled', notificationsEnabled.toString());
  }, [notificationsEnabled, safelyPersistToStorage]);
  
  useEffect(() => {
    safelyPersistToStorage('sentinel-sound-volume', soundVolume.toString());
  }, [soundVolume, safelyPersistToStorage]);

  // Improved audio loading with better error handling
  useEffect(() => {
    if (!audioRef.current) {
      try {
        // Create audio element and set its properties
        audioRef.current = initializeAudio(ALERT_SOUND_URL);
        
        if (audioRef.current) {
          const handleAudioLoaded = () => {
            console.log('Audio loaded successfully');
            setAudioLoaded(true);
            setAudioError(null);
          };
          
          const handleAudioError = (e: ErrorEvent) => {
            console.error('Error loading audio:', e);
            setAudioLoaded(false);
            setAudioError('Failed to load alert sound');
          };
          
          audioRef.current.addEventListener('canplaythrough', handleAudioLoaded);
          audioRef.current.addEventListener('error', handleAudioError as EventListener);
        }
      } catch (error) {
        console.error('Error initializing audio:', error);
        setAudioError('Failed to initialize audio');
      }
    }
    
    return () => {
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.removeEventListener('canplaythrough', () => setAudioLoaded(true));
        audioRef.current.removeEventListener('error', () => setAudioError('Failed to load alert sound'));
      }
    };
  }, []);
  
  const { 
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
    apiConnected,
    blockchainConnected,
    connectToSources,
    disconnect,
    fetchThreatData,
    fetchBlockchainData
  } = useThreatData(persistedSettings);
  
  const toggleSound = useCallback(() => {
    setSoundEnabled(!soundEnabled);
  }, [soundEnabled]);
  
  // Connect to sources when settings are available and connection is not active
  useEffect(() => {
    if (persistedSettings.apiUrl && persistedSettings.blockchainUrl && !isConnected && !isLoading && !isReconnecting) {
      try {
        console.log('Attempting to connect with stored settings');
        connectToSources();
      } catch (error) {
        console.error('Error connecting to sources:', error);
      }
    }
  }, [persistedSettings, isConnected, isLoading, isReconnecting, connectToSources]);
  
  // Handle high severity threats for alerts
  useEffect(() => {
    if (!threatData.length || !notificationsEnabled) return;
    
    try {
      const highSeverityThreats = getNewHighSeverityThreats(threatData, alertHistory);
      
      if (highSeverityThreats.length > 0) {
        setCurrentAlert(highSeverityThreats[0]);
        setAlertHistory(prev => [...prev, highSeverityThreats[0].id]);
        
        // Play sound for high severity threats if enabled
        if (soundEnabled && audioRef.current && audioLoaded) {
          playAudio(audioRef.current, soundVolume).catch(err => {
            console.error('Failed to play alert sound:', err);
          });
        }
      }
    } catch (error) {
      console.error('Error processing threats for alerts:', error);
    }
  }, [threatData, notificationsEnabled, alertHistory, soundEnabled, soundVolume, audioLoaded]);
  
  // Safely validate URLs and connect
  const handleConnect = useCallback((apiKey: string, apiUrl: string, blockchainUrl: string) => {
    try {
      // Store the new settings
      const newSettings = { apiKey, apiUrl, blockchainUrl };
      setPersistedSettings(newSettings);
      
      // Try to connect with the new settings
      connectToSources();
    } catch (err) {
      console.error("Error in handleConnect:", err);
    }
  }, [connectToSources]);
  
  const handleDisconnect = useCallback(() => {
    disconnect();
  }, [disconnect]);
  
  const handleReset = useCallback(() => {
    const newSettings = { apiKey: '', apiUrl: '', blockchainUrl: '' };
    setPersistedSettings(newSettings);
    disconnect();
  }, [disconnect]);
  
  useEffect(() => {
    if (isConnected && blockchainConnected) {
      // We've removed the toast notification here
      // to reduce the number of notifications
    }
  }, [isConnected, blockchainConnected]);
  
  // Handle opening settings dialog
  const handleOpenSettings = useCallback(() => {
    if (settingsTriggerRef.current) {
      settingsTriggerRef.current.click();
    }
  }, []);
  
  return (
    <ThemeProvider defaultTheme="dark">
      <div className="min-h-screen bg-gradient-to-br from-background to-secondary/10">
        <Header 
          isConnected={isConnected}
          connectionSettings={persistedSettings}
          onDisconnect={handleDisconnect}
          onReset={handleReset}
          onConnect={handleConnect}
          soundEnabled={soundEnabled}
          setSoundEnabled={setSoundEnabled}
          notificationsEnabled={notificationsEnabled}
          setNotificationsEnabled={setNotificationsEnabled}
          soundVolume={soundVolume}
          setSoundVolume={setSoundVolume}
          connectionError={connectionError}
          ref={settingsTriggerRef}
        />
        
        <main className="container mx-auto pt-24 pb-16 px-4 sm:px-6">
          {(isConnected || isReconnecting) && (
            <div className="mb-4">
              <ConnectionStatus 
                isConnected={isConnected} 
                lastUpdated={lastUpdated}
                isReconnecting={isReconnecting}
                reconnectAttempts={reconnectAttempts} 
                usingFallbackData={usingFallbackData}
                apiConnected={apiConnected}
                blockchainConnected={blockchainConnected}
              />
            </div>
          )}
          
          <div className="space-y-6">
            {!isConnected && !isLoading && !isReconnecting ? (
              <div className="h-[70vh] flex flex-col items-center justify-center">
                <div className="text-center space-y-6 max-w-lg">
                  <Shield className="h-20 w-20 text-primary opacity-20 mx-auto" />
                  <h2 className="text-2xl font-semibold">Sentinel Dashboard</h2>
                  <p className="text-muted-foreground">
                    Connect to your threat intelligence API and blockchain ledger to view 
                    real-time security insights and threat data.
                  </p>
                  {connectionError && (
                    <div className="text-red-500 p-4 bg-red-500/10 rounded-lg text-sm">
                      <AlertOctagon className="h-4 w-4 inline-block mr-2" />
                      {connectionError}
                    </div>
                  )}
                  <div className="flex justify-center">
                    <Button 
                      onClick={handleOpenSettings}
                      className="connect-button group"
                    >
                      <Settings className="h-4 w-4 mr-2" />
                      Configure Connection
                    </Button>
                  </div>
                </div>
              </div>
            ) : (
              <>
                <section className="grid gap-6 mb-6">
                  <div className="w-full">
                    <ThreatStats {...threatStats} />
                  </div>
                </section>
                
                <section className="grid grid-cols-1 md:grid-cols-12 gap-6 mb-6">
                  <div className="md:col-span-5 h-auto">
                    <div className="bg-background/60 backdrop-blur-sm border border-border/50 rounded-lg shadow-md h-full overflow-hidden">
                      <div className="flex flex-col h-full max-h-[500px]">
                        <div className="p-4 border-b border-border/50">
                          <h2 className="text-lg font-medium">Live Attack Feed</h2>
                        </div>
                        <div className="flex-grow overflow-auto p-0">
                          <LiveAttackFeed threats={threatData} />
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="md:col-span-7 h-[500px]">
                    <div className="bg-background/60 backdrop-blur-sm border border-border/50 rounded-lg shadow-md h-full overflow-hidden">
                      <div className="p-4 border-b border-border/50">
                        <h2 className="text-lg font-medium">Threat Analysis</h2>
                      </div>
                      <div className="p-4 h-[calc(100%-61px)]">
                        <ThreatChart threats={threatData} />
                      </div>
                    </div>
                  </div>
                </section>
                
                <section className="grid grid-cols-1 md:grid-cols-12 gap-6 mb-6">
                  <div className="md:col-span-8 h-[400px]">
                    <div className="bg-background/60 backdrop-blur-sm border border-border/50 rounded-lg shadow-md h-full overflow-hidden">
                      <div className="p-4 border-b border-border/50">
                        <h2 className="text-lg font-medium">Blockchain Ledger</h2>
                      </div>
                      <div className="h-[calc(100%-61px)] overflow-auto">
                        <BlockchainViewer data={blockchainData} />
                        {blockchainData && blockchainData.chain.length > 0 && (
                          <div className="flex justify-center mt-4 pb-4">
                            <button 
                              onClick={() => navigate('/blockchain-analytics')}
                              className="text-sm bg-primary/10 hover:bg-primary/20 text-primary px-4 py-2 rounded-md transition-colors"
                            >
                              View Advanced Analytics
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="md:col-span-4 h-[400px]">
                    <BlockedIPs />
                  </div>
                </section>

                <section className="mb-6">
                  <div className="bg-background/60 backdrop-blur-sm border border-border/50 rounded-lg shadow-md">
                    <div className="p-4 border-b border-border/50">
                      <h2 className="text-lg font-medium">Threat Trends</h2>
                    </div>
                    <div className="p-4">
                      <ThreatTrends threats={threatData} />
                    </div>
                  </div>
                </section>
              </>
            )}
          </div>
        </main>
        
        {/* Floating notification at bottom */}
        {currentAlert && (
          <AlertBanner 
            threat={currentAlert} 
            onClose={() => setCurrentAlert(null)} 
            soundEnabled={soundEnabled}
            soundVolume={soundVolume}
            toggleSound={toggleSound}
          />
        )}
      </div>
    </ThemeProvider>
  );
};

export default Index;