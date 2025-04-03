import { useState, forwardRef, Ref } from 'react';
import { Dialog, DialogContent, DialogTrigger } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { SettingsPanel } from '@/features/settings/SettingsPanel';
import { AlertTriangle, Bell, BellOff, Settings, Shield, Volume2, VolumeX } from 'lucide-react';
import { Link } from 'react-router-dom';

interface HeaderProps {
  isConnected?: boolean;
  connectionSettings?: {
    apiKey: string;
    apiUrl: string;
    blockchainUrl: string;
  };
  onConnect?: (apiKey: string, apiUrl: string, blockchainUrl: string) => void;
  onDisconnect?: () => void;
  onReset?: () => void;
  soundEnabled?: boolean;
  setSoundEnabled?: (enabled: boolean) => void;
  notificationsEnabled?: boolean;
  setNotificationsEnabled?: (enabled: boolean) => void;
  soundVolume?: number;
  setSoundVolume?: (volume: number) => void;
  connectionError?: string | null;
  title?: string;
  subtitle?: string;
}

const Header = forwardRef<HTMLButtonElement, HeaderProps>(function Header(
  {
    isConnected,
    connectionSettings = { apiKey: '', apiUrl: '', blockchainUrl: '' },
    onConnect,
    onDisconnect,
    onReset,
    soundEnabled = false,
    setSoundEnabled,
    notificationsEnabled = false,
    setNotificationsEnabled,
    soundVolume = 70,
    setSoundVolume,
    connectionError,
    title = "Sentinel",
    subtitle
  },
  ref
) {
  const [settingsOpen, setSettingsOpen] = useState(false);
  
  // Check if it's a simplified header (e.g., for CyberGuard)
  const isSimplifiedHeader = !onConnect;

  const handleSettingsTriggerClick = () => {
    setSettingsOpen(true);
  };
  
  return (
    <header className="fixed top-0 left-0 right-0 dark-nav z-50">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-semibold">{title}</h1>
          </Link>
          
          {subtitle && (
            <span className="ml-2 text-xs text-muted-foreground">
              {subtitle}
            </span>
          )}
          
          {isConnected && !isSimplifiedHeader && (
            <span className="ml-2 text-xs px-2 py-0.5 bg-green-500/20 text-green-500 rounded-full">
              Connected
            </span>
          )}
        </div>
        
        <div className="flex items-center space-x-2">
          {/* Navigation Links */}
          <div className="hidden md:flex items-center mr-4 space-x-1">
            <Link to="/">
              <Button variant="ghost" size="sm">Dashboard</Button>
            </Link>
            <Link to="/cyber-guard">
              <Button variant="ghost" size="sm">CyberGuard</Button>
            </Link>
            <Link to="/blockchain-analytics">
              <Button variant="ghost" size="sm">Blockchain</Button>
            </Link>
          </div>
          
          {!isSimplifiedHeader && (
            <>
              <Button
                variant="ghost"
                size="icon"
                title={soundEnabled ? "Mute sounds" : "Enable sounds"}
                onClick={() => setSoundEnabled && setSoundEnabled(!soundEnabled)}
              >
                {soundEnabled ? <Volume2 className="h-5 w-5" /> : <VolumeX className="h-5 w-5 text-muted-foreground" />}
              </Button>
              
              <Button
                variant="ghost"
                size="icon"
                title={notificationsEnabled ? "Disable notifications" : "Enable notifications"}
                onClick={() => setNotificationsEnabled && setNotificationsEnabled(!notificationsEnabled)}
              >
                {notificationsEnabled ? <Bell className="h-5 w-5" /> : <BellOff className="h-5 w-5 text-muted-foreground" />}
              </Button>
              
              <Dialog open={settingsOpen} onOpenChange={setSettingsOpen}>
                <DialogTrigger asChild>
                  <Button 
                    id="settings-trigger"
                    ref={ref}
                    variant={connectionError ? "destructive" : "outline"} 
                    size="sm"
                    className="flex items-center"
                    onClick={handleSettingsTriggerClick}
                  >
                    {connectionError && <AlertTriangle className="h-4 w-4 mr-2" />}
                    <Settings className="h-4 w-4 mr-2" />
                    Settings
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[600px] max-h-[90vh] overflow-y-auto">
                  {onConnect && onDisconnect && onReset && (
                    <SettingsPanel
                      connectionSettings={connectionSettings}
                      isConnected={!!isConnected}
                      onConnect={onConnect}
                      onDisconnect={onDisconnect}
                      onReset={onReset}
                      soundEnabled={soundEnabled}
                      setSoundEnabled={setSoundEnabled || (() => {})}
                      notificationsEnabled={notificationsEnabled}
                      setNotificationsEnabled={setNotificationsEnabled || (() => {})}
                      soundVolume={soundVolume}
                      setSoundVolume={setSoundVolume || (() => {})}
                      connectionError={connectionError || null}
                    />
                  )}
                </DialogContent>
              </Dialog>
            </>
          )}
        </div>
      </div>
    </header>
  );
});

Header.displayName = "Header";

export default Header;
