import { useState, useEffect } from 'react';
import Header from '@/components/Header';
import BlockchainGraphs from '@/components/charts/BlockchainGraphs';
import ConnectionStatus from '@/features/settings/ConnectionStatus';
import { useThreatData } from '@/hooks/useThreatData';
import { Toaster, toast } from 'sonner';
import { ThemeProvider } from '@/components/theme-provider';
import { Database, ArrowLeft, AlertCircle } from 'lucide-react';
import { getFromStorage, saveToStorage } from '@/utils/storageUtils';
import { useNavigate } from 'react-router-dom';

const BlockchainAnalytics = () => {
  console.log('BlockchainAnalytics rendering');
  const navigate = useNavigate();
  // Load persisted settings from localStorage
  const [persistedSettings, setPersistedSettings] = useState(() => 
    getFromStorage('sentinel-connection-settings', {
      apiKey: '',
      apiUrl: '',
      blockchainUrl: '',
    })
  );
  
  const { 
    isConnected,
    isLoading,
    connectionError,
    lastUpdated,
    blockchainData,
    reconnectAttempts,
    isReconnecting,
    apiConnected,
    blockchainConnected,
    connectToSources,
    disconnect
  } = useThreatData(persistedSettings);
  
  // Connect to sources when settings are available and connection is not active
  useEffect(() => {
    if (persistedSettings.blockchainUrl && !isConnected && !isLoading && !isReconnecting) {
      try {
        console.log('Attempting to connect with stored settings:', persistedSettings);
        connectToSources();
      } catch (error) {
        console.error('Error connecting to sources:', error);
      }
    }
  }, [persistedSettings, isConnected, isLoading, isReconnecting, connectToSources]);
  
  useEffect(() => {
    console.log('BlockchainData in analytics:', blockchainData);
    console.log('Connected status:', isConnected, blockchainConnected);
    
    if (isConnected && blockchainConnected) {
      // Notify users about the chatbot feature when connected
      toast.info(
        'Blockchain AI Assistant is available! Click the chat icon in the bottom right corner to analyze your threat data.',
        {
          duration: 5000,
          id: 'chatbot-notification', // Prevent duplicate toasts
        }
      );
    }
  }, [blockchainData, isConnected, blockchainConnected]);
  
  const handleDisconnect = () => {
    disconnect();
  };
  
  const handleReset = () => {
    const newSettings = { apiKey: '', apiUrl: '', blockchainUrl: '' };
    setPersistedSettings(newSettings);
    saveToStorage('sentinel-connection-settings', newSettings);
    disconnect();
  };
  
  const handleConnect = (apiKey: string, apiUrl: string, blockchainUrl: string) => {
    try {
      // Store the new settings
      const newSettings = { apiKey, apiUrl, blockchainUrl };
      setPersistedSettings(newSettings);
      saveToStorage('sentinel-connection-settings', newSettings);
      
      // Try to connect with the new settings
      connectToSources();
    } catch (err) {
      console.error("Error in handleConnect:", err);
    }
  };
  
  return (
    <ThemeProvider defaultTheme="dark">
      <div className="min-h-screen bg-gradient-to-br from-background to-secondary/10">
        <Toaster position="top-right" richColors closeButton />
        <Header 
          isConnected={isConnected}
          connectionSettings={persistedSettings}
          onDisconnect={handleDisconnect}
          onReset={handleReset}
          onConnect={handleConnect}
          soundEnabled={false}
          setSoundEnabled={() => {}}
          notificationsEnabled={false}
          setNotificationsEnabled={() => {}}
          soundVolume={0}
          setSoundVolume={() => {}}
          connectionError={connectionError}
        />
        
        <main className="container mx-auto pt-24 pb-16 px-4 sm:px-6">
          {(isConnected || isReconnecting) && (
            <div className="mb-4">
              <ConnectionStatus 
                isConnected={isConnected} 
                lastUpdated={lastUpdated}
                isReconnecting={isReconnecting}
                reconnectAttempts={reconnectAttempts} 
                usingFallbackData={false}
                apiConnected={apiConnected}
                blockchainConnected={blockchainConnected}
              />
            </div>
          )}
          
          <div className="space-y-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center">
                <Database className="h-6 w-6 text-primary mr-2" />
                <h1 className="text-2xl font-semibold">Blockchain Analytics</h1>
              </div>
              <button 
                onClick={() => navigate('/')}
                className="flex items-center text-sm bg-primary/10 hover:bg-primary/20 text-primary px-4 py-2 rounded-md transition-colors"
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Dashboard
              </button>
            </div>
            
            {!isConnected && !isLoading && !isReconnecting ? (
              <div className="h-[70vh] flex flex-col items-center justify-center">
                <div className="text-center space-y-6 max-w-lg">
                  <Database className="h-20 w-20 text-primary opacity-20 mx-auto" />
                  <h2 className="text-2xl font-semibold">Blockchain Analytics</h2>
                  <p className="text-muted-foreground">
                    Connect to your blockchain ledger to view detailed analytics and visualizations of block data.
                  </p>
                  {connectionError && (
                    <div className="text-red-500 p-4 bg-red-500/10 rounded-lg text-sm">
                      <div className="flex items-start">
                        <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0 mt-0.5" />
                        <div>{connectionError}</div>
                      </div>
                    </div>
                  )}
                  {!persistedSettings.blockchainUrl && (
                    <div className="text-yellow-500 p-4 bg-yellow-500/10 rounded-lg text-sm">
                      <div className="flex items-start">
                        <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0 mt-0.5" />
                        <div>Blockchain URL is not configured. Please configure it in the settings.</div>
                      </div>
                    </div>
                  )}
                  <div className="flex justify-center">
                    <button 
                      onClick={() => document.getElementById('settings-trigger')?.click()}
                      className="connect-button group"
                    >
                      Configure Connection
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <BlockchainGraphs data={blockchainData} />
            )}
          </div>
        </main>
      </div>
    </ThemeProvider>
  );
};

export default BlockchainAnalytics; 