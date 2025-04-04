import { useState, useEffect, useRef } from 'react';
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
  AlertTriangle,
  Flame,
  Database as DatabaseIcon,
  Check,
  X,
  Loader2,
  Paintbrush
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
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { toast } from '@/components/ui/use-toast';

// Add Firebase imports
import { initializeApp } from 'firebase/app';
import { getDatabase, ref, set } from 'firebase/database';

interface SettingsTabProps {
  icon: LucideIcon;
  label: string;
  active: boolean;
  onClick: () => void;
  className?: string;
}

const SettingsTab = ({ icon: Icon, label, active, onClick, className = '' }: SettingsTabProps) => (
  <button 
    className={`settings-tab ${active ? 'active' : ''} ${className}`}
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
  connectionError: string | null;
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
  const [activeTab, setActiveTab] = useState('firebase');
  
  // Firebase state
  const [firebaseConnected, setFirebaseConnected] = useState(false);
  const [isFirebaseConnecting, setIsFirebaseConnecting] = useState(false);
  const [firebaseError, setFirebaseError] = useState<string | null>(null);
  const firebaseAppRef = useRef<any>(null);
  const firebaseDatabaseRef = useRef<any>(null);
  
  // Firebase configuration fields
  const [firebaseApiKey, setFirebaseApiKey] = useState("AIzaSyBSbonwVE3PPXIIrSrvrB75u2AQ_B_Tni4");
  const [firebaseAuthDomain, setFirebaseAuthDomain] = useState("discraft-c1c41.firebaseapp.com");
  const [firebaseDatabaseURL, setFirebaseDatabaseURL] = useState("https://discraft-c1c41-default-rtdb.firebaseio.com");
  const [firebaseProjectId, setFirebaseProjectId] = useState("discraft-c1c41");
  const [firebaseStorageBucket, setFirebaseStorageBucket] = useState("discraft-c1c41.appspot.com");
  const [firebaseMessagingSenderId, setFirebaseMessagingSenderId] = useState("525620150766");
  const [firebaseAppId, setFirebaseAppId] = useState("1:525620150766:web:a426e68d206c68764aceff");

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

  // Firebase connection function
  const connectToFirebase = () => {
    console.log('🔥 Attempting to connect to Firebase...');
    setIsFirebaseConnecting(true);
    setFirebaseError(null);
    
    try {
      // Log all config values (without sensitive info)
      console.log('🔥 Firebase configuration:', {
        authDomain: firebaseAuthDomain,
        databaseURL: firebaseDatabaseURL,
        projectId: firebaseProjectId,
        storageBucket: firebaseStorageBucket
      });
      
      if (!firebaseAppRef.current) {
        console.log('🔥 No existing Firebase app found, initializing new connection');
        // Initialize Firebase with configuration
        const firebaseConfig = {
          apiKey: firebaseApiKey,
          authDomain: firebaseAuthDomain,
          databaseURL: firebaseDatabaseURL,
          projectId: firebaseProjectId,
          storageBucket: firebaseStorageBucket,
          messagingSenderId: firebaseMessagingSenderId,
          appId: firebaseAppId
        };
        
        // Initialize Firebase
        try {
          console.log('🔥 Initializing Firebase app...');
          firebaseAppRef.current = initializeApp(firebaseConfig);
          console.log('🔥 Firebase app initialized successfully:', firebaseAppRef.current.name);
        } catch (initError) {
          console.error('🔥 Error initializing Firebase app:', initError);
          throw new Error(`Firebase initialization failed: ${(initError as Error).message}`);
        }
        
        // Get a reference to the database service
        try {
          console.log('🔥 Getting database reference...');
          firebaseDatabaseRef.current = getDatabase(firebaseAppRef.current);
          console.log('🔥 Database reference obtained successfully');
        } catch (dbError) {
          console.error('🔥 Error getting database reference:', dbError);
          throw new Error(`Database connection failed: ${(dbError as Error).message}`);
        }
        
        console.log('🔥 Firebase initialized successfully from Settings');
        
        // Set connection status
        setFirebaseConnected(true);
        
        // Log connection time
        const connectTime = new Date().toISOString();
        console.log('🔥 Logging connection timestamp:', connectTime);
        try {
          set(ref(firebaseDatabaseRef.current, 'lastConnect'), {
            timestamp: connectTime,
            client: 'Sentinel Dashboard Settings',
            status: 'connected'
          }).then(() => {
            console.log('🔥 Connection logged successfully to Firebase');
          }).catch((error) => {
            console.error('🔥 Error logging connection to Firebase:', error);
          });
        } catch (refError) {
          console.error('🔥 Error creating reference for lastConnect:', refError);
        }
        
        // Notify success
        console.log('🔥 Dispatching firebase-connected event (connected: true)');
        window.dispatchEvent(new CustomEvent('firebase-connected', { 
          detail: { 
            connected: true,
            app: firebaseAppRef.current,
            database: firebaseDatabaseRef.current
          } 
        }));
      } else {
        console.log('🔥 Firebase already initialized from Settings, reusing existing connection');
        setFirebaseConnected(true);
        
        // Re-notify success with existing connection
        console.log('🔥 Dispatching firebase-connected event with existing connection');
        window.dispatchEvent(new CustomEvent('firebase-connected', { 
          detail: { 
            connected: true,
            app: firebaseAppRef.current,
            database: firebaseDatabaseRef.current
          } 
        }));
      }
    } catch (error) {
      console.error('🔥 Firebase initialization error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown connection error';
      setFirebaseError(errorMessage);
      setFirebaseConnected(false);
      
      // Notify failure
      console.log('🔥 Dispatching firebase-connected event (connected: false)');
      window.dispatchEvent(new CustomEvent('firebase-connected', { 
        detail: { connected: false, error: errorMessage } 
      }));
    } finally {
      console.log('🔥 Firebase connection attempt completed');
      setIsFirebaseConnecting(false);
    }
  };

  // Disconnect from Firebase
  const disconnectFromFirebase = () => {
    console.log('🔥 Attempting to disconnect from Firebase...');
    if (firebaseAppRef.current) {
      try {
        // Log disconnection
        if (firebaseDatabaseRef.current) {
          console.log('🔥 Logging disconnection to Firebase');
          set(ref(firebaseDatabaseRef.current, 'lastConnect'), {
            timestamp: new Date().toISOString(),
            client: 'Sentinel Dashboard Settings',
            status: 'disconnected'
          }).catch((error) => {
            console.error('🔥 Error logging disconnection:', error);
          });
        }
        
        // Reset references
        console.log('🔥 Resetting Firebase app and database references');
        firebaseAppRef.current = null;
        firebaseDatabaseRef.current = null;
        setFirebaseConnected(false);
        
        console.log('🔥 Successfully disconnected from Firebase');
        
        // Notify disconnection
        console.log('🔥 Dispatching firebase-connected event (connected: false)');
        window.dispatchEvent(new CustomEvent('firebase-connected', { 
          detail: { connected: false } 
        }));
      } catch (error) {
        console.error('🔥 Error disconnecting from Firebase:', error);
        const errorMessage = error instanceof Error ? error.message : 'Unknown disconnection error';
        setFirebaseError(errorMessage);
      }
    } else {
      console.log('🔥 No active Firebase connection to disconnect');
    }
  };

  return (
    <Sheet>
      <SheetTrigger id="settings-trigger" asChild>
        <Button variant="ghost" size="icon" className="relative">
          <Settings className="h-5 w-5" />
          {connectionError && (
            <span className="absolute -top-1 -right-1 block h-2.5 w-2.5 rounded-full bg-red-600 border border-white" />
          )}
        </Button>
      </SheetTrigger>
      <SheetContent className="w-[400px] sm:w-[540px] overflow-y-auto">
        <SheetHeader>
          <SheetTitle>
            <div className="flex items-center">
              Settings
              {connectionError && (
                <Badge variant="destructive" className="ml-2 gap-1 px-1.5 py-0">
                  <span className="rounded-full h-1.5 w-1.5 bg-white"></span>
                  <span className="text-xs">Error</span>
                </Badge>
              )}
            </div>
          </SheetTitle>
          <SheetDescription>
            Configure your dashboard settings and connections.
          </SheetDescription>
        </SheetHeader>
        
        <Tabs className="mt-6" value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="firebase" className="text-xs">
              <Flame className="mr-1 h-3.5 w-3.5" />
              Firebase
            </TabsTrigger>
            <TabsTrigger value="appearance" className="text-xs">
              <Paintbrush className="mr-1 h-3.5 w-3.5" />
              Appearance
            </TabsTrigger>
            <TabsTrigger value="notifications" className="text-xs">
              <Bell className="mr-1 h-3.5 w-3.5" />
              Notifications
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="firebase" className="space-y-6 animate-in fade-in-50 duration-300">
            {firebaseError && (
              <Alert variant="destructive" className="mb-4">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription className="ml-2">
                  {firebaseError}
                </AlertDescription>
              </Alert>
            )}
            
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Firebase Configuration</h3>
              <div className="grid gap-2">
                <Label htmlFor="firebase-apiKey">API Key</Label>
                <Input 
                  id="firebase-apiKey" 
                  value={firebaseApiKey} 
                  onChange={e => setFirebaseApiKey(e.target.value)}
                  disabled={firebaseConnected || isFirebaseConnecting}
                  placeholder="Firebase API Key" 
                />
              </div>
              
              <div className="grid gap-2">
                <Label htmlFor="firebase-authDomain">Auth Domain</Label>
                <Input 
                  id="firebase-authDomain" 
                  value={firebaseAuthDomain} 
                  onChange={e => setFirebaseAuthDomain(e.target.value)}
                  disabled={firebaseConnected || isFirebaseConnecting}
                  placeholder="projectname.firebaseapp.com" 
                />
              </div>
              
              <div className="grid gap-2">
                <Label htmlFor="firebase-databaseURL">Database URL</Label>
                <Input 
                  id="firebase-databaseURL" 
                  value={firebaseDatabaseURL} 
                  onChange={e => setFirebaseDatabaseURL(e.target.value)}
                  disabled={firebaseConnected || isFirebaseConnecting}
                  placeholder="https://projectname.firebaseio.com" 
                />
              </div>
              
              <div className="grid gap-2">
                <Label htmlFor="firebase-projectId">Project ID</Label>
                <Input 
                  id="firebase-projectId" 
                  value={firebaseProjectId} 
                  onChange={e => setFirebaseProjectId(e.target.value)}
                  disabled={firebaseConnected || isFirebaseConnecting}
                  placeholder="project-id" 
                />
              </div>
              
              <div className="grid grid-cols-2 gap-2">
                <Button
                  onClick={connectToFirebase}
                  disabled={firebaseConnected || isFirebaseConnecting}
                  className="gap-1"
                >
                  {isFirebaseConnecting ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Connecting...
                    </>
                  ) : firebaseConnected ? (
                    <>
                      <Check className="h-4 w-4" />
                      Connected
                    </>
                  ) : (
                    <>
                      <Link2 className="h-4 w-4" />
                      Connect Firebase
                    </>
                  )}
                </Button>
                
                {firebaseConnected && (
                  <Button
                    variant="outline"
                    className="gap-1"
                    onClick={() => {
                      setFirebaseConnected(false);
                      toast.info('Disconnected from Firebase');
                    }}
                  >
                    <X className="h-4 w-4" />
                    Disconnect
                  </Button>
                )}
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="appearance" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Theme Settings</h3>
              <div className="flex flex-col gap-2">
                <Label htmlFor="theme">Select Theme</Label>
                <div className="grid grid-cols-3 gap-2">
                  <ThemeButton
                    theme="light"
                    currentTheme={theme}
                    onClick={() => setTheme("light")}
                  />
                  <ThemeButton
                    theme="dark"
                    currentTheme={theme}
                    onClick={() => setTheme("dark")}
                  />
                  <ThemeButton
                    theme="system"
                    currentTheme={theme}
                    onClick={() => setTheme("system")}
                  />
                </div>
              </div>
              
              <div className="space-y-2">
                <h4 className="font-medium">Display Preferences</h4>
                <div className="flex items-center space-x-2">
                  <Switch 
                    id="bankai-mode"
                    checked={false}
                    onCheckedChange={() => {
                      toast({
                        title: "Coming Soon",
                        description: "Advanced display preferences will be available in an upcoming update.",
                        variant: "default",
                      });
                    }}
                  />
                  <Label htmlFor="bankai-mode">Advanced Mode (Coming Soon)</Label>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="notifications" className="space-y-6">
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Alert Settings</h3>
              
              <div className="grid gap-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="notifications" className="cursor-pointer flex items-center">
                    <Bell className="h-4 w-4 mr-2" />
                    Enable Notifications
                  </Label>
                  <Switch 
                    id="notifications" 
                    checked={notificationsEnabled} 
                    onCheckedChange={setNotificationsEnabled} 
                  />
                </div>
              </div>
              
              <div className="grid gap-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="sound" className="cursor-pointer flex items-center">
                    <Volume2 className="h-4 w-4 mr-2" />
                    Enable Sound Effects
                  </Label>
                  <Switch 
                    id="sound" 
                    checked={soundEnabled} 
                    onCheckedChange={setSoundEnabled} 
                  />
                </div>
              </div>
              
              {soundEnabled && (
                <div className="grid gap-2">
                  <Label htmlFor="volume">Sound Volume: {soundVolume}%</Label>
                  <Slider 
                    id="volume" 
                    min={0} 
                    max={100} 
                    step={1} 
                    defaultValue={[soundVolume]} 
                    onValueChange={values => setSoundVolume(values[0])} 
                  />
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
};

export default SettingsPanel;
