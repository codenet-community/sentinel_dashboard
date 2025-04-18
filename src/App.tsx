import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { ThemeProvider } from "@/components/theme-provider";
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";
import BlockchainAnalytics from "./pages/BlockchainAnalytics";
import CyberGuardDashboard from "./pages/CyberGuardDashboard";
import CyberForge from "./pages/CyberForge";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider defaultTheme="dark">
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/blockchain-analytics" element={<BlockchainAnalytics />} />
            <Route path="/blockchainanalytics" element={<Navigate to="/blockchain-analytics" replace />} />
            <Route path="/cyber-guard" element={<CyberGuardDashboard />} />
            <Route path="/cyberguard" element={<Navigate to="/cyber-guard" replace />} />
            <Route path="/cyber-forge" element={<CyberForge />} />
            <Route path="/cyberforge" element={<Navigate to="/cyber-forge" replace />} />
            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
