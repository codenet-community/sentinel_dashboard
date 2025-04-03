import { useState, useEffect } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Network, Shield, Volume2, Bell, Trash2, Settings, Wifi, RefreshCcw, Save, Check, X, Info } from 'lucide-react';
import { toast } from 'sonner';
import { isValidUrl } from '@/utils/dataUtils';

interface SettingsPanelProps {
  connectionSettings: {
    apiKey: string;
    apiUrl: string;
    blockchainUrl: string;
  };
  isConnected: boolean;
  onConnect: (apiKey: string, apiUrl: string, blockchainUrl: string) => void;
  onDisconnect: () => void;
  onReset: () => void;
  soundEnabled: boolean;
  setSoundEnabled: (enabled: boolean) => void;
  notificationsEnabled: boolean;
  setNotificationsEnabled: (enabled: boolean) => void;
  soundVolume: number;
  setSoundVolume: (volume: number) => void;
  connectionError: string | null;
}

export const SettingsPanel = ({
  connectionSettings = { apiKey: '', apiUrl: '', blockchainUrl: '' },
  isConnected = false,
  onConnect,
  onDisconnect,
  onReset,
  soundEnabled = false,
  setSoundEnabled = () => {},
  notificationsEnabled = false,
  setNotificationsEnabled = () => {},
  soundVolume = 70,
  setSoundVolume = () => {},
  connectionError = null
}: SettingsPanelProps) => {
  const [apiKey, setApiKey] = useState(connectionSettings.apiKey || '');
  const [apiUrl, setApiUrl] = useState(connectionSettings.apiUrl || '');
  const [blockchainUrl, setBlockchainUrl] = useState(connectionSettings.blockchainUrl || '');
  const [useDemoData, setUseDemoData] = useState(false);
  const [errors, setErrors] = useState<{
    apiUrl?: string;
    blockchainUrl?: string;
  }>({});

  useEffect(() => {
    // Update state when props change
    setApiKey(connectionSettings.apiKey || '');
    setApiUrl(connectionSettings.apiUrl || '');
    setBlockchainUrl(connectionSettings.blockchainUrl || '');
  }, [connectionSettings]);
  
  const validateInputs = () => {
    // Skip validation if using demo data
    if (useDemoData) return true;
    
    const newErrors: {
      apiUrl?: string;
      blockchainUrl?: string;
    } = {};
    
    if (!apiUrl) {
      newErrors.apiUrl = "API URL is required";
    } else if (!isValidUrl(apiUrl)) {
      newErrors.apiUrl = "Invalid URL format";
    }
    
    if (!blockchainUrl) {
      newErrors.blockchainUrl = "Blockchain URL is required";
    } else if (!isValidUrl(blockchainUrl)) {
      newErrors.blockchainUrl = "Invalid URL format";
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };
  
  const handleConnect = () => {
    if (!validateInputs()) return;
    
    try {
      // If using demo data, use demo URLs
      if (useDemoData) {
        onConnect(apiKey, 'https://demo.api.sentinel/threats', 'https://demo.api.sentinel/blockchain');
        toast.success('Connected to demo data');
      } else {
        onConnect(apiKey, apiUrl, blockchainUrl);
        toast.success('Connection settings saved');
      }
    } catch (error) {
      toast.error('Failed to connect');
      console.error('Connection error:', error);
    }
  };
  
  const handleDemoToggle = (checked: boolean) => {
    setUseDemoData(checked);
    if (checked) {
      // Clear any validation errors when switching to demo mode
      setErrors({});
    }
  };
  
  const handleDisconnect = () => {
    onDisconnect();
    toast.info('Disconnected from services');
  };
  
  const handleReset = () => {
    setApiKey('');
    setApiUrl('');
    setBlockchainUrl('');
    setUseDemoData(false);
    onReset();
    toast.info('Settings reset to default');
  };
  
  return (
    <Tabs defaultValue="connection" className="w-full">
      <TabsList className="grid grid-cols-3 mb-4">
        <TabsTrigger value="connection" className="flex items-center gap-2">
          <Network className="h-4 w-4" />
          <span className="hidden sm:inline">Connection</span>
        </TabsTrigger>
        <TabsTrigger value="notifications" className="flex items-center gap-2">
          <Bell className="h-4 w-4" />
          <span className="hidden sm:inline">Notifications</span>
        </TabsTrigger>
        <TabsTrigger value="about" className="flex items-center gap-2">
          <Shield className="h-4 w-4" />
          <span className="hidden sm:inline">About</span>
        </TabsTrigger>
      </TabsList>
      
      <TabsContent value="connection">
        <Card>
          <CardHeader>
            <CardTitle>Connection Settings</CardTitle>
            <CardDescription>
              Configure your threat intelligence API and blockchain connections
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {connectionError && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-md text-red-500 text-sm mb-4">
                <div className="flex items-start">
                  <X className="h-5 w-5 mr-2 flex-shrink-0 mt-0.5" />
                  <div>{connectionError}</div>
                </div>
              </div>
            )}
            
            <div className="flex items-center justify-between pb-4 border-b border-border">
              <div className="space-y-0.5">
                <Label htmlFor="test-mode">Test Mode</Label>
                <p className="text-sm text-muted-foreground">
                  Use demo data to test the dashboard
                </p>
              </div>
              <Switch
                id="test-mode"
                checked={useDemoData}
                onCheckedChange={handleDemoToggle}
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="apiKey">API Key (Optional)</Label>
              <Input 
                id="apiKey" 
                placeholder="Your API key" 
                value={apiKey} 
                onChange={(e) => setApiKey(e.target.value)} 
                type="password"
                disabled={useDemoData}
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="apiUrl">
                Threat API URL <span className="text-red-500">*</span>
              </Label>
              <Input 
                id="apiUrl" 
                placeholder="https://api.example.com/threats" 
                value={apiUrl} 
                onChange={(e) => {
                  setApiUrl(e.target.value);
                  if (errors.apiUrl) {
                    setErrors({ ...errors, apiUrl: undefined });
                  }
                }}
                className={errors.apiUrl ? "border-red-500" : ""}
                disabled={useDemoData}
              />
              {errors.apiUrl && (
                <p className="text-red-500 text-xs mt-1">{errors.apiUrl}</p>
              )}
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="blockchainUrl">
                Blockchain URL <span className="text-red-500">*</span>
              </Label>
              <Input 
                id="blockchainUrl" 
                placeholder="https://api.example.com/blockchain" 
                value={blockchainUrl} 
                onChange={(e) => {
                  setBlockchainUrl(e.target.value);
                  if (errors.blockchainUrl) {
                    setErrors({ ...errors, blockchainUrl: undefined });
                  }
                }}
                className={errors.blockchainUrl ? "border-red-500" : ""}
                disabled={useDemoData}
              />
              {errors.blockchainUrl && (
                <p className="text-red-500 text-xs mt-1">{errors.blockchainUrl}</p>
              )}
              {useDemoData && (
                <p className="text-blue-500 text-xs mt-2">
                  <Info className="h-3 w-3 inline mr-1" />
                  Using demo data mode - no real endpoints needed
                </p>
              )}
            </div>
          </CardContent>
          <CardFooter className="flex justify-between">
            <div className="flex gap-2">
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleReset}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Reset
              </Button>
              
              {isConnected && (
                <Button 
                  variant="destructive" 
                  size="sm"
                  onClick={handleDisconnect}
                >
                  <Wifi className="h-4 w-4 mr-2" />
                  Disconnect
                </Button>
              )}
            </div>
            
            <Button 
              onClick={handleConnect} 
              disabled={!useDemoData && (!apiUrl || !blockchainUrl)}
            >
              {isConnected ? (
                <>
                  <RefreshCcw className="h-4 w-4 mr-2" />
                  Update Connection
                </>
              ) : (
                <>
                  <Wifi className="h-4 w-4 mr-2" />
                  Connect
                </>
              )}
            </Button>
          </CardFooter>
        </Card>
      </TabsContent>
      
      <TabsContent value="notifications">
        <Card>
          <CardHeader>
            <CardTitle>Notification Settings</CardTitle>
            <CardDescription>
              Configure alerts and notification preferences
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="notifications">Alert Notifications</Label>
                <p className="text-sm text-muted-foreground">
                  Show notifications for high severity threats
                </p>
              </div>
              <Switch
                id="notifications"
                checked={notificationsEnabled}
                onCheckedChange={setNotificationsEnabled}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="sound">Alert Sounds</Label>
                <p className="text-sm text-muted-foreground">
                  Play sound when high severity threats are detected
                </p>
              </div>
              <Switch
                id="sound"
                checked={soundEnabled}
                onCheckedChange={setSoundEnabled}
              />
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label htmlFor="volume">Sound Volume</Label>
                <span className="text-sm text-muted-foreground">{soundVolume}%</span>
              </div>
              <Slider
                id="volume"
                defaultValue={[soundVolume]}
                max={100}
                step={1}
                disabled={!soundEnabled}
                onValueChange={(value) => setSoundVolume(value[0])}
                className={!soundEnabled ? "opacity-50" : ""}
              />
            </div>
          </CardContent>
        </Card>
      </TabsContent>
      
      <TabsContent value="about">
        <Card>
          <CardHeader>
            <CardTitle>About Sentinel Dashboard</CardTitle>
            <CardDescription>
              Real-time blockchain-secured threat intelligence
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <p>
              Sentinel is an advanced security dashboard that monitors and displays real-time threat intelligence.
              The system securely records all detected threats on an immutable blockchain ledger, ensuring data
              integrity and providing a tamper-proof audit trail.
            </p>
            
            <div className="space-y-2">
              <h4 className="font-medium">Features:</h4>
              <ul className="list-disc pl-5 space-y-1">
                <li>Real-time threat monitoring and alerting</li>
                <li>Blockchain-verified threat data</li>
                <li>Advanced threat analytics and visualization</li>
                <li>Attack pattern recognition</li>
                <li>Secure, immutable security audit trail</li>
              </ul>
            </div>
            
            <div className="py-2">
              <p className="text-xs text-muted-foreground">
                Version 1.0.0 • © 2023 Sentinel Security
              </p>
            </div>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
};

export default SettingsPanel;
