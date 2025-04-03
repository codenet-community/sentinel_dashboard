import { useState, useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AlertTriangle, CheckCircle2, ArrowDownToLine, Copy, ExternalLink } from 'lucide-react';
import { toast } from 'sonner';

interface ThreatAnalysisViewProps {
  analysisResult: string;
}

// Helper function to parse sections from the analysis result
const parseSections = (content: string) => {
  // This is a simple implementation. You could enhance this to be more robust
  // or even adapt to different response formats.
  
  const sections: Record<string, string> = {};
  
  // Try to identify sections by common headers
  const identifySection = (text: string, keywordMap: Record<string, string>) => {
    for (const [keyword, sectionName] of Object.entries(keywordMap)) {
      if (text.toLowerCase().includes(keyword.toLowerCase())) {
        return sectionName;
      }
    }
    return null;
  };
  
  // Split the content by common section markers
  const lines = content.split('\n');
  let currentSection = 'overview';
  sections[currentSection] = '';
  
  const sectionKeywords: Record<string, string> = {
    'verification': 'verification',
    'attack type': 'verification',
    'criticality': 'verification',
    'risk': 'verification',
    
    'metrics': 'risk_assessment',
    'score': 'risk_assessment',
    'assessment': 'risk_assessment',
    'evaluation': 'risk_assessment',
    
    'mitigation': 'mitigation',
    'remediation': 'mitigation',
    'action': 'mitigation',
    'steps': 'mitigation',
    'step': 'mitigation',
    
    'recommendation': 'recommendations',
    'tuning': 'recommendations',
    'model': 'recommendations',
    'enhance': 'recommendations',
    
    'conclusion': 'conclusion',
    'summary': 'conclusion'
  };
  
  for (const line of lines) {
    // Check if this line might be a section header
    if (line.trim().length > 0 && (line.includes(':') || line.match(/^\d+\./))) {
      const potentialSection = identifySection(line, sectionKeywords);
      if (potentialSection) {
        currentSection = potentialSection;
        sections[currentSection] = sections[currentSection] || '';
      }
    }
    
    // Add the line to the current section
    sections[currentSection] += line + '\n';
  }
  
  return sections;
};

const ThreatAnalysisView = ({ analysisResult }: ThreatAnalysisViewProps) => {
  const [sections, setSections] = useState<Record<string, string>>({});
  
  useEffect(() => {
    if (analysisResult) {
      setSections(parseSections(analysisResult));
    }
  }, [analysisResult]);
  
  const handleCopyToClipboard = () => {
    navigator.clipboard.writeText(analysisResult);
    toast.success('Analysis copied to clipboard');
  };
  
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h3 className="text-xl font-semibold">Gemini Analysis</h3>
        <Button variant="outline" size="sm" onClick={handleCopyToClipboard}>
          <Copy className="h-4 w-4 mr-2" />
          Copy
        </Button>
      </div>
      
      {/* Summary Card */}
      {sections.verification && (
        <Card>
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <div className="mt-1">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <h4 className="font-medium mb-2">Threat Verification</h4>
                <div className="text-sm space-y-2">
                  <p className="whitespace-pre-wrap">{sections.verification}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
      
      {/* Risk Assessment */}
      {sections.risk_assessment && (
        <Card>
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <div className="mt-1">
                <AlertTriangle className="h-5 w-5 text-amber-500" />
              </div>
              <div>
                <h4 className="font-medium mb-2">Risk Assessment</h4>
                <div className="text-sm space-y-2">
                  <p className="whitespace-pre-wrap">{sections.risk_assessment}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
      
      {/* Mitigation Strategy */}
      {sections.mitigation && (
        <>
          <Separator />
          
          <div>
            <h4 className="font-medium mb-4">Mitigation Strategy</h4>
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <div className="whitespace-pre-wrap">{sections.mitigation}</div>
            </div>
          </div>
        </>
      )}
      
      {/* Recommendations */}
      {sections.recommendations && (
        <>
          <Separator />
          
          <div>
            <h4 className="font-medium mb-4">Recommendations</h4>
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <div className="whitespace-pre-wrap">{sections.recommendations}</div>
            </div>
          </div>
        </>
      )}
      
      {/* Conclusion */}
      {sections.conclusion && (
        <>
          <Separator />
          
          <div>
            <h4 className="font-medium mb-4">Conclusion</h4>
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <div className="whitespace-pre-wrap">{sections.conclusion}</div>
            </div>
          </div>
        </>
      )}
      
      {/* If no sections were detected, show the raw analysis */}
      {Object.keys(sections).length === 0 && (
        <div className="prose prose-sm max-w-none dark:prose-invert">
          <div className="whitespace-pre-wrap">{analysisResult}</div>
        </div>
      )}
    </div>
  );
};

export default ThreatAnalysisView; 