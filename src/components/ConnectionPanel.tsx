import { useState, useEffect } from 'react';
import { Loader2, LockKeyhole, Link2 } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useToast } from '@/components/ui/use-toast';

interface ConnectionPanelProps {
  onConnect: (apiKey: string, apiUrl: string, blockchainUrl: string) => void;
  isLoading: boolean;
  isConnected: boolean;
  initialValues?: {
    apiKey: string;
    apiUrl: string;
    blockchainUrl: string;
  };
}

const ConnectionPanel = ({ onConnect, isLoading, isConnected, initialValues }: ConnectionPanelProps) => {
  const { toast } = useToast();
  const [apiKey, setApiKey] = useState(initialValues?.apiKey || '');
  const [apiUrl, setApiUrl] = useState(initialValues?.apiUrl || 'http://localhost:8000/fake-attacks');
  const [blockchainUrl, setBlockchainUrl] = useState(initialValues?.blockchainUrl || 'http://localhost:8000/blockchain');
  const [showPanel, setShowPanel] = useState(!isConnected);
  
  // Update form values when initialValues change
  useEffect(() => {
    if (initialValues) {
      setApiKey(initialValues.apiKey || '');
      setApiUrl(initialValues.apiUrl || 'http://localhost:8000/fake-attacks');
      setBlockchainUrl(initialValues.blockchainUrl || 'http://localhost:8000/blockchain');
    }
  }, [initialValues]);
  
  const handleConnect = () => {
    if (!apiUrl) {
      toast({
        title: "API URL is required",
        description: "Please provide a valid API endpoint URL",
        variant: "destructive",
      });
      return;
    }
    
    if (!blockchainUrl) {
      toast({
        title: "Blockchain URL is required",
        description: "Please provide a valid blockchain endpoint URL",
        variant: "destructive",
      });
      return;
    }
    
    onConnect(apiKey, apiUrl, blockchainUrl);
  };
  
  if (!showPanel && isConnected) {
    return (
      <div className="flex justify-end">
        <Button 
          variant="outline" 
          size="sm" 
          className="text-xs gap-1 glass-card"
          onClick={() => setShowPanel(true)}
        >
          <Link2 className="h-3.5 w-3.5" />
          Connection Settings
        </Button>
      </div>
    );
  }
  
  return (
    <Card className="animate-fade-in glass-card">
      <CardHeader>
        <CardTitle>Data Source Connection</CardTitle>
        <CardDescription>
          Connect to your threat intelligence API and blockchain for real-time monitoring
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <label htmlFor="apiKey" className="text-sm font-medium">
            API Key <span className="text-muted-foreground">(Optional)</span>
          </label>
          <div className="relative">
            <Input
              id="apiKey"
              type="password"
              placeholder="Enter your API key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="pl-9"
            />
            <LockKeyhole className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          </div>
          <p className="text-xs text-muted-foreground">
            Leave empty if your API doesn't require authentication
          </p>
        </div>
        
        <div className="space-y-2">
          <label htmlFor="apiUrl" className="text-sm font-medium">
            Threat API URL <span className="text-red-500">*</span>
          </label>
          <Input
            id="apiUrl"
            type="text"
            placeholder="https://your-threat-api.com/endpoint"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            required
          />
        </div>
        
        <div className="space-y-2">
          <label htmlFor="blockchainUrl" className="text-sm font-medium">
            Blockchain API URL <span className="text-red-500">*</span>
          </label>
          <Input
            id="blockchainUrl"
            type="text"
            placeholder="https://your-blockchain-api.com/endpoint"
            value={blockchainUrl}
            onChange={(e) => setBlockchainUrl(e.target.value)}
            required
          />
        </div>
        
        <div className="flex justify-between items-center pt-2">
          {isConnected && (
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={() => setShowPanel(false)}
              className="text-sm"
            >
              Hide Settings
            </Button>
          )}
          
          <Button 
            className="connect-button ml-auto"
            onClick={handleConnect}
            disabled={isLoading || (!apiUrl || !blockchainUrl)}
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Connecting...
              </>
            ) : isConnected ? (
              'Reconnect'
            ) : (
              'Connect'
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

export default ConnectionPanel;