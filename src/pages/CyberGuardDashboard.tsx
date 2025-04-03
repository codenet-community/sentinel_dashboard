import { useState, useEffect } from 'react';
import Header from '@/components/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Shield, AlertTriangle, RefreshCw, Database } from 'lucide-react';
import { useThreatData } from '@/hooks/useThreatData';
import { getFromStorage } from '@/utils/storageUtils';
import { useGeminiAnalysis } from '@/hooks/useGeminiAnalysis';
import ChatbotSuggester from '@/components/chatbot/ChatbotSuggester';
import { Toaster, toast } from 'sonner'; 

export interface PredictionDetails {
  is_anomaly: boolean;
  is_zero_day: boolean;
  top_features: string[];
}

export interface EnhancedThreatDetail extends ThreatDetail {
  confidence_score?: number;
  anomaly_score?: number;
  zero_day_score?: number;
  prediction_details?: PredictionDetails;
}

export interface EnhancedThreatData extends ThreatData {
  details: EnhancedThreatDetail;
}

const CyberGuardDashboard = () => {
  // Load persisted settings from localStorage
  const persistedSettings = getFromStorage('sentinel-connection-settings', {
    apiKey: '',
    apiUrl: '',
    blockchainUrl: '',
  });
  
  // Use the existing hooks to fetch threat data
  const { 
    isConnected,
    isLoading,
    error,
    threatData,
    fetchBlockchainData,
    apiConnected,
    blockchainConnected,
    isReconnecting,
    blockchainData,
    connectToSources
  } = useThreatData(persistedSettings);

  // Connect to blockchain on component mount if we have settings
  useEffect(() => {
    // Check if we need to connect
    if (persistedSettings.blockchainUrl && !isConnected && !isLoading && !isReconnecting) {
      console.log('Attempting to connect with stored settings in CyberGuard');
      connectToSources();
    }
  }, [persistedSettings, isConnected, isLoading, isReconnecting, connectToSources]);

  // Log connection status for debugging
  useEffect(() => {
    console.log('CyberGuard connection status:', { 
      isConnected, 
      blockchainConnected, 
      hasBlockchainData: !!blockchainData,
      chainLength: blockchainData?.chain?.length || 0
    });
  }, [isConnected, blockchainConnected, blockchainData]);

  // Refresh the threat data 
  const handleRefreshData = () => {
    console.log('Refreshing blockchain data');
    fetchBlockchainData();
    
    toast.info('Refreshing blockchain data...', {
      duration: 2000
    });
  };

  // Force connect handler
  const handleForceConnect = () => {
    console.log('Force connecting to blockchain');
    connectToSources();
    
    toast.info('Connecting to blockchain...', {
      duration: 2000
    });
  };

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Toaster position="top-right" />
      <Header title="CyberGuard" subtitle="Advanced Threat Analysis" />
      
      <main className="flex-1 p-6 container">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary" />
              CyberGuard AI Assistant
            </h1>
            <p className="text-muted-foreground">
              Advanced cybersecurity analysis powered by AI
            </p>
          </div>
          
          <div className="flex items-center gap-2">
            <Badge variant={blockchainConnected ? "success" : "destructive"} className="px-3 py-1">
              {blockchainConnected ? "Connected" : "Disconnected"}
            </Badge>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={handleRefreshData}
              disabled={isLoading || isReconnecting}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading || isReconnecting ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={handleForceConnect}
              disabled={isLoading || isReconnecting}
            >
              <Database className="h-4 w-4 mr-2" />
              Connect
            </Button>
          </div>
        </div>
        
        {error && (
          <Card className="mb-6 border-destructive">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-5 w-5" />
                <p>Error: {error}</p>
              </div>
            </CardContent>
          </Card>
        )}
        
        {/* Full page chatbot with connection debugging info */}
        <div className="space-y-4">
          {/* Debug information card - remove in production */}
          <Card className="bg-slate-50 dark:bg-slate-900/50">
            <CardContent className="p-3 text-xs">
              <div className="space-y-1">
                <p><strong>Connection Debug:</strong> isConnected={String(isConnected)}, blockchainConnected={String(blockchainConnected)}</p>
                <p><strong>Blockchain Data:</strong> {blockchainData ? `Available with ${blockchainData.chain?.length || 0} blocks` : 'Not available'}</p>
                <p><strong>Loading State:</strong> isLoading={String(isLoading)}, isReconnecting={String(isReconnecting)}</p>
              </div>
            </CardContent>
          </Card>
          
          <div className="h-[calc(100vh-260px)]">
            <ChatbotSuggester 
              blockchainData={blockchainData}
              isConnected={isConnected || blockchainConnected || (blockchainData?.chain?.length > 0)}
              className="h-full"
            />
          </div>
        </div>
      </main>
    </div>
  );
};

export default CyberGuardDashboard; 