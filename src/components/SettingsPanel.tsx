import { useState, useEffect } from 'react';
import { 
  Bell, 
  Moon, 
  Sun, 
  LucideIcon, 
  Settings, 
  Volume2, 
  VolumeX, 
  Link2, 
  LogOut, 
  RotateCcw,
  KeyRound,
  Globe,
  Server,
  ExternalLink,
  AlertTriangle
} from 'lucide-react';
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger 
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useTheme } from '@/components/theme-provider';

interface SettingsTabProps {
  icon: LucideIcon;
  label: string;
  active: boolean;
  onClick: () => void;
}

const SettingsTab = ({ icon: Icon, label, active, onClick }: SettingsTabProps) => (
  <button 
    className={`settings-tab ${active ? 'active' : ''}`}
    onClick={onClick}
  >
    <Icon className="h-4 w-4" />
    <span>{label}</span>
  </button>
);

interface SettingsPanelProps {
  connectionSettings: {
    apiKey: string;
    apiUrl: string;
    blockchainUrl: string;
  };
  isConnected: boolean;
  onDisconnect: () => void;
  onReset: () => void;
  onConnect: (apiKey: string, apiUrl: string, blockchainUrl: string) => void;
  soundEnabled: boolean;
  setSoundEnabled: (enabled: boolean) => void;
  notificationsEnabled: boolean;
  setNotificationsEnabled: (enabled: boolean) => void;
  soundVolume: number;
  setSoundVolume: (volume: number) => void;
  connectionError?: string | null;
}

const SettingsPanel = ({
  connectionSettings,
  isConnected,
  onDisconnect,
  onReset,
  onConnect,
  soundEnabled,
  setSoundEnabled,
  notificationsEnabled,
  setNotificationsEnabled,
  soundVolume,
  setSoundVolume,
  connectionError
}: SettingsPanelProps) => {
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('connection');
  const [apiKey, setApiKey] = useState(connectionSettings.apiKey);
  const [apiUrl, setApiUrl] = useState(connectionSettings.apiUrl);
  const [blockchainUrl, setBlockchainUrl] = useState(connectionSettings.blockchainUrl);
  const [isOpen, setIsOpen] = useState(false);
  const [apiInputMode, setApiInputMode] = useState<'full' | 'host'>('full');
  const [blockchainInputMode, setBlockchainInputMode] = useState<'full' | 'host'>('full');
  const [apiHost, setApiHost] = useState('');
  const [blockchainHost, setBlockchainHost] = useState('');
  const [apiPath, setApiPath] = useState('/fake-attacks');
  const [blockchainPath, setBlockchainPath] = useState('/chain');

  useEffect(() => {
    setApiKey(connectionSettings.apiKey || '');
    setApiUrl(connectionSettings.apiUrl || '');
    setBlockchainUrl(connectionSettings.blockchainUrl || '');
    
    if (connectionSettings.apiUrl) {
      try {
        const url = new URL(connectionSettings.apiUrl);
        setApiHost(url.origin);
        setApiPath(url.pathname);
      } catch (e) {
      }
    }
    
    if (connectionSettings.blockchainUrl) {
      try {
        const url = new URL(connectionSettings.blockchainUrl);
        setBlockchainHost(url.origin);
        setBlockchainPath(url.pathname);
      } catch (e) {
      }
    }
  }, [connectionSettings]);

  const getFullApiUrl = () => {
    if (apiInputMode === 'full') {
      return apiUrl;
    } else {
      let host = apiHost;
      if (!host.startsWith('http')) {
        host = `https://${host}`;
      }
      let path = apiPath || '/fake-attacks';
      if (!path.startsWith('/')) {
        path = `/${path}`;
      }
      return `${host}${path}`;
    }
  };

  const getFullBlockchainUrl = () => {
    if (blockchainInputMode === 'full') {
      return blockchainUrl;
    } else {
      let host = blockchainHost;
      if (!host.startsWith('http')) {
        host = `https://${host}`;
      }
      let path = blockchainPath || '/chain';
      if (!path.startsWith('/')) {
        path = `/${path}`;
      }
      return `${host}${path}`;
    }
  };

  const handleConnect = () => {
    onConnect(apiKey, getFullApiUrl(), getFullBlockchainUrl());
    setIsOpen(false);
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="rounded-full fixed left-4 top-4 z-50">
          <Settings className="h-5 w-5" />
          <span className="sr-only">Settings</span>
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle>Dashboard Settings</DialogTitle>
        </DialogHeader>
        
        <div className="flex mt-4">
          <div className="w-1/4 space-y-2 pr-4 border-r border-border">
            <SettingsTab 
              icon={Link2} 
              label="Connection" 
              active={activeTab === 'connection'} 
              onClick={() => setActiveTab('connection')} 
            />
            <SettingsTab 
              icon={Bell} 
              label="General" 
              active={activeTab === 'general'} 
              onClick={() => setActiveTab('general')} 
            />
          </div>
          
          <div className="w-3/4 pl-6">
            {activeTab === 'general' && (
              <div className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Theme</h3>
                  <div className="flex items-center gap-4">
                    <Button
                      variant={theme === 'light' ? 'default' : 'outline'}
                      size="sm"
                      className="gap-1"
                      onClick={() => setTheme('light')}
                    >
                      <Sun className="h-4 w-4" />
                      Light
                    </Button>
                    <Button
                      variant={theme === 'dark' ? 'default' : 'outline'}
                      size="sm"
                      className="gap-1"
                      onClick={() => setTheme('dark')}
                    >
                      <Moon className="h-4 w-4" />
                      Dark
                    </Button>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Notifications</h3>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="notifications" className="flex items-center gap-2">
                        <Bell className="h-4 w-4" />
                        Enable Notifications
                      </Label>
                      <Switch 
                        id="notifications" 
                        checked={notificationsEnabled} 
                        onCheckedChange={setNotificationsEnabled} 
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Show alerts when new threats are detected
                    </p>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Sound Alerts</h3>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="sound-toggle" className="flex items-center gap-2">
                        {soundEnabled ? (
                          <Volume2 className="h-4 w-4" />
                        ) : (
                          <VolumeX className="h-4 w-4" />
                        )}
                        Enable Sound Alerts
                      </Label>
                      <Switch 
                        id="sound-toggle" 
                        checked={soundEnabled} 
                        onCheckedChange={setSoundEnabled} 
                      />
                    </div>
                    
                    <div className="pt-2">
                      <Label htmlFor="sound-volume" className="text-xs text-muted-foreground pb-2 block">
                        Alert Volume
                      </Label>
                      <div className="flex items-center gap-4">
                        <VolumeX className="h-3 w-3 text-muted-foreground" />
                        <Slider
                          id="sound-volume"
                          defaultValue={[soundVolume]}
                          max={100}
                          step={1}
                          disabled={!soundEnabled}
                          onValueChange={(value) => setSoundVolume(value[0])}
                          className="flex-1"
                        />
                        <Volume2 className="h-3 w-3 text-muted-foreground" />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            {activeTab === 'connection' && (
              <div className="space-y-6">
                {connectionError && (
                  <Alert variant="destructive" className="mb-4">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription className="ml-2">
                      {connectionError}
                    </AlertDescription>
                  </Alert>
                )}
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Connection Status</h3>
                  <div className="p-4 rounded-md bg-muted/50 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">Status</span>
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></span>
                        <span className="text-sm">{isConnected ? 'Connected' : 'Disconnected'}</span>
                      </div>
                    </div>
                    
                    {isConnected && (
                      <>
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-muted-foreground">API URL</span>
                          <span className="text-sm font-mono truncate max-w-[250px]">{connectionSettings.apiUrl}</span>
                        </div>
                        
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-muted-foreground">Blockchain URL</span>
                          <span className="text-sm font-mono truncate max-w-[250px]">{connectionSettings.blockchainUrl}</span>
                        </div>
                      </>
                    )}
                  </div>
                </div>
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Connection Settings</h3>
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <Label htmlFor="api-key" className="flex items-center gap-1.5 text-xs">
                        <KeyRound className="h-3.5 w-3.5" />
                        API Key (Optional)
                      </Label>
                      <Input
                        id="api-key"
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        placeholder="Enter your API key if required"
                        className="font-mono text-sm"
                        type="password"
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <Label className="flex items-center gap-1.5 text-xs">
                        <Globe className="h-3.5 w-3.5" />
                        API URL
                      </Label>
                      
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-1 text-xs">
                          <Button
                            type="button"
                            size="sm"
                            variant={apiInputMode === 'full' ? 'default' : 'outline'}
                            className="text-xs h-7 px-2"
                            onClick={() => setApiInputMode('full')}
                          >
                            <ExternalLink className="h-3 w-3 mr-1" />
                            Full URL
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant={apiInputMode === 'host' ? 'default' : 'outline'}
                            className="text-xs h-7 px-2"
                            onClick={() => setApiInputMode('host')}
                          >
                            <Server className="h-3 w-3 mr-1" />
                            Host + Path
                          </Button>
                        </div>
                      </div>
                      
                      {apiInputMode === 'full' ? (
                        <Input
                          id="api-url"
                          value={apiUrl}
                          onChange={(e) => setApiUrl(e.target.value)}
                          placeholder="http://your-api.com/threats"
                          className="font-mono text-sm"
                          required
                        />
                      ) : (
                        <div className="space-y-2">
                          <div className="space-y-1">
                            <Label htmlFor="api-host" className="text-xs text-muted-foreground">Host/Domain</Label>
                            <Input
                              id="api-host"
                              value={apiHost}
                              onChange={(e) => setApiHost(e.target.value)}
                              placeholder="example.ngrok-free.app"
                              className="font-mono text-sm"
                              required
                            />
                          </div>
                          <div className="space-y-1">
                            <Label htmlFor="api-path" className="text-xs text-muted-foreground">Path</Label>
                            <Input
                              id="api-path"
                              value={apiPath}
                              onChange={(e) => setApiPath(e.target.value)}
                              placeholder="/fake-attacks"
                              className="font-mono text-sm"
                            />
                          </div>
                          <div className="p-2 bg-muted/30 rounded text-xs font-mono">
                            {getFullApiUrl()}
                          </div>
                        </div>
                      )}
                    </div>
                    
                    <div className="space-y-2 mt-4">
                      <Label className="flex items-center gap-1.5 text-xs">
                        <Link2 className="h-3.5 w-3.5" />
                        Blockchain URL
                      </Label>
                      
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-1 text-xs">
                          <Button
                            type="button"
                            size="sm"
                            variant={blockchainInputMode === 'full' ? 'default' : 'outline'}
                            className="text-xs h-7 px-2"
                            onClick={() => setBlockchainInputMode('full')}
                          >
                            <ExternalLink className="h-3 w-3 mr-1" />
                            Full URL
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant={blockchainInputMode === 'host' ? 'default' : 'outline'}
                            className="text-xs h-7 px-2"
                            onClick={() => setBlockchainInputMode('host')}
                          >
                            <Server className="h-3 w-3 mr-1" />
                            Host + Path
                          </Button>
                        </div>
                      </div>
                      
                      {blockchainInputMode === 'full' ? (
                        <Input
                          id="blockchain-url"
                          value={blockchainUrl}
                          onChange={(e) => setBlockchainUrl(e.target.value)}
                          placeholder="http://your-blockchain.com/ledger"
                          className="font-mono text-sm"
                          required
                        />
                      ) : (
                        <div className="space-y-2">
                          <div className="space-y-1">
                            <Label htmlFor="blockchain-host" className="text-xs text-muted-foreground">Host/Domain</Label>
                            <Input
                              id="blockchain-host"
                              value={blockchainHost}
                              onChange={(e) => setBlockchainHost(e.target.value)}
                              placeholder="example.ngrok-free.app"
                              className="font-mono text-sm"
                              required
                            />
                          </div>
                          <div className="space-y-1">
                            <Label htmlFor="blockchain-path" className="text-xs text-muted-foreground">Path</Label>
                            <Input
                              id="blockchain-path"
                              value={blockchainPath}
                              onChange={(e) => setBlockchainPath(e.target.value)}
                              placeholder="/chain"
                              className="font-mono text-sm"
                            />
                          </div>
                          <div className="p-2 bg-muted/30 rounded text-xs font-mono">
                            {getFullBlockchainUrl()}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div className="pt-2">
                    <Button
                      onClick={handleConnect}
                      className="w-full"
                      disabled={apiInputMode === 'full' ? !apiUrl : !apiHost || 
                               blockchainInputMode === 'full' ? !blockchainUrl : !blockchainHost}
                    >
                      Connect
                    </Button>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Connection Actions</h3>
                  <div className="flex flex-col gap-2">
                    {isConnected && (
                      <Button 
                        variant="destructive" 
                        className="w-full" 
                        onClick={onDisconnect}
                      >
                        <LogOut className="h-4 w-4 mr-2" />
                        Disconnect
                      </Button>
                    )}
                    
                    <Button 
                      variant="outline" 
                      className="w-full" 
                      onClick={onReset}
                    >
                      <RotateCcw className="h-4 w-4 mr-2" />
                      Reset Connection Settings
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default SettingsPanel;
