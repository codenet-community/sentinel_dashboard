import { useState, useCallback } from 'react';

interface GeminiAnalysisProps {
  apiKey?: string;
}

export const useGeminiAnalysis = (props?: GeminiAnalysisProps) => {
  const [analysisResult, setAnalysisResult] = useState<string | null>(null);
  const [isAnalysisLoading, setIsAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  
  // Use the provided API key or the default one
  const apiKey = props?.apiKey || 'AIzaSyD_TgK9asHn_CVEqe_seDN9JYR2ebZT11U';
  const geminiEndpoint = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent';
  
  const analyzeWithGemini = useCallback(async (threatJson: string) => {
    setIsAnalysisLoading(true);
    setAnalysisError(null);
    
    try {
      const requestBody = {
        contents: [
          {
            parts: [
              {
                text: `You are CyberGuard, an advanced cybersecurity threat analysis assistant. 
                
                Please analyze the following threat event data and provide intelligent, actionable solutions based on the attack type:
                
                ${threatJson}
                
                Your analysis should include:
                1. Verification of the attack type and criticality.
                2. Evaluation of metrics (confidence_score, anomaly_score, zero_day_score) to determine risk level.
                3. Specific mitigation strategies and remediation actions for this attack.
                4. Recommendations on how the prediction model can be fine-tuned based on the top features.
                5. A comprehensive response addressing both the detected threat and suggested actions.
                
                Format your response in a clear, structured manner suitable for cybersecurity professionals.`
              }
            ]
          }
        ],
        generationConfig: {
          temperature: 0.2,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: 1024,
        }
      };
      
      const response = await fetch(`${geminiEndpoint}?key=${apiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to analyze threat with Gemini API');
      }
      
      const data = await response.json();
      const analysisText = data.candidates?.[0]?.content?.parts?.[0]?.text;
      
      if (!analysisText) {
        throw new Error('No analysis result returned from Gemini API');
      }
      
      setAnalysisResult(analysisText);
      return analysisText;
    } catch (error) {
      console.error('Error analyzing threat with Gemini:', error);
      setAnalysisError(error instanceof Error ? error.message : 'Unknown error occurred');
      return null;
    } finally {
      setIsAnalysisLoading(false);
    }
  }, [apiKey, geminiEndpoint]);
  
  return {
    analyzeWithGemini,
    analysisResult,
    isAnalysisLoading,
    analysisError,
    resetAnalysis: () => setAnalysisResult(null)
  };
};

export default useGeminiAnalysis; 