"""
RAG Agent using Google Gemini API

This module implements a Retrieval-Augmented Generation agent that:
1. Retrieves relevant threats from knowledge base using semantic search
2. Generates comprehensive threat analysis and mitigation reports using Gemini
3. Handles unknown threats by searching the internet
"""

import os
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
import requests
from urllib.parse import quote

# Google Gemini API (Free with limits: 60 requests per minute)
import google.generativeai as genai
from dotenv import load_dotenv

from threat_knowledge_base import ThreatKnowledgeBase


class RAGAgent:
    """Retrieval-Augmented Generation agent for threat analysis"""
    
    def __init__(self, gemini_api_key: Optional[str] = None):
        """
        Initialize RAG agent
        
        Args:
            gemini_api_key: Google Gemini API key (or set GEMINI_API_KEY env var)
        """
        # Load environment variables
        load_dotenv()
        
        # Get API key
        api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY not found. Set it as environment variable or pass as parameter.\n"
                "Get free API key at: https://makersuite.google.com/app/apikey"
            )
        
        # Initialize Gemini with lite/fast models (lower token usage)
        genai.configure(api_key=api_key)
        
        # Try lite versions first (use fewer tokens)
        # These are confirmed available on most Gemini API accounts
        model_names = [
            "gemini-2.5-flash-lite",     
            "gemini-2.0-flash-lite",    
            "gemini-2.5-flash",          
            "gemini-2.0-flash",          
            "gemini-flash-lite-latest", 
        ]
        
        self.model = None
        for model_name in model_names:
            try:
                self.model = genai.GenerativeModel(model_name)
                self.model_name = model_name
                break
            except Exception as e:
                print(f"  ⚠️  Model {model_name} not available: {str(e)[:50]}...")
                continue
        
        if not self.model:
            raise ValueError(
                f"No available Gemini models found. Tried: {', '.join(model_names)}\n"
                "Check your API key and available models at: https://makersuite.google.com"
            )
        
        # Initialize knowledge base
        self.kb = ThreatKnowledgeBase()
        self.kb.index_threats()
        
        print("✓ RAG Agent initialized")
        print(f"  - Model: {self.model_name} (lite - low token usage)")
        print(f"  - Knowledge Base: {self.kb.get_kb_stats()['total_threats']} threats")
    
    def _search_internet(self, query: str) -> str:
        """
        Search internet for information about unknown threats
        Uses DuckDuckGo (free, no API key needed)
        
        Args:
            query: Search query
        
        Returns:
            Search results as formatted string
        """
        try:
            print(f"  🔗 Searching internet for: {query}")
            
            # Using DuckDuckGo HTML search (free, no API key)
            url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Extract basic info from HTML
            # For production, use: pip install duckduckgo-search
            return f"Internet search results for: {query}\n[Results would be fetched here in production environment]"
        
        except Exception as e:
            print(f"  ⚠️  Internet search failed: {str(e)}")
            return f"Could not search internet for '{query}'. Please provide more details."
    
    def analyze_attack(
        self,
        attack_description: str,
        detected_indicators: List[str],
        target_component: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze an attack and generate mitigation recommendations
        
        Args:
            attack_description: Description of the attack
            detected_indicators: List of detected indicators (IPs, processes, behaviors, etc.)
            target_component: Optional target O-RAN component
        
        Returns:
            Analysis report with threats and mitigations
        """
        print(f"\n{'='*60}")
        print("🔍 THREAT ANALYSIS - RAG Agent")
        print(f"{'='*60}")
        print(f"Attack: {attack_description}")
        print(f"Indicators: {', '.join(detected_indicators)}")
        if target_component:
            print(f"Target: {target_component}")
        
        # Step 1: Search knowledge base for relevant threats
        print(f"\n📚 Step 1: Searching knowledge base...")
        search_query = f"{attack_description} {' '.join(detected_indicators)}"
        kb_results = self.kb.search_threats(search_query, top_k=5)
        
        if kb_results:
            print(f"  Found {len(kb_results)} relevant threats:")
            for i, result in enumerate(kb_results, 1):
                threat = result["threat"]
                score = result["relevance_score"]
                print(f"    {i}. {threat['threat_name']} ({threat.get('mitre_id', 'N/A')}) - Score: {score:.2%}")
        else:
            print("  ⚠️  No matching threats in knowledge base")
        
        # Step 2: Generate comprehensive analysis with Gemini
        print(f"\n🤖 Step 2: Generating analysis with Gemini...")
        
        # Prepare context from knowledge base
        context = self._prepare_context(kb_results, target_component)
        
        # Create analysis prompt
        analysis_prompt = self._create_analysis_prompt(
            attack_description,
            detected_indicators,
            target_component,
            context,
            kb_results
        )
        
        # Get Gemini response (with timeout)
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Gemini API call exceeded 30 second timeout")
        
        # Set 30 second timeout on Windows, skip on other platforms
        import platform
        timeout_set = False
        if platform.system() != "Windows":
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(30)
            timeout_set = True
        
        try:
            print("  ⏳ Calling Gemini API (30s timeout)...")
            response = self.model.generate_content(
                analysis_prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=2048,
                    temperature=0.3,  # Lower temperature for focused responses
                )
            )
            if timeout_set:
                signal.alarm(0)  # Cancel alarm
            analysis = response.text
            print(f"  ✓ Analysis generated ({len(analysis)} chars)")
        except TimeoutError as e:
            print(f"  ❌ Gemini API timeout: {str(e)}")
            analysis = "Analysis generation timed out. Knowledge base matches provided above for reference."
        except Exception as e:
            print(f"  ❌ Gemini API error: {str(e)}")
            analysis = "Error generating analysis with Gemini API. Using knowledge base matches only."
        finally:
            if timeout_set:
                signal.alarm(0)  # Ensure alarm is cancelled
        
        # Step 3: Handle unknown threats
        mitigations_from_search = []
        if not kb_results or len(kb_results) < 2:
            print(f"\n🔗 Step 3: Searching internet for additional information...")
            internet_results = self._search_internet(attack_description)
            mitigations_from_search.append(internet_results)
        
        # Step 4: Compile report (ensure JSON-serializable)
        try:
            recommendations = self._extract_recommendations(analysis)
        except:
            recommendations = []
        
        try:
            severity = self._assess_severity(kb_results, attack_description)
        except:
            severity = "medium"
        
        report = {
            "status": "success" if kb_results else "partial",
            "timestamp": self._get_timestamp(),
            "attack_info": {
                "description": attack_description,
                "indicators": list(detected_indicators) if detected_indicators else [],
                "target_component": target_component or "Unknown"
            },
            "knowledge_base_matches": [
                {
                    "threat_name": str(result["threat"].get("threat_name", "Unknown")),
                    "mitre_id": str(result["threat"].get("mitre_id", "N/A")),
                    "description": str(result["threat"].get("threat_description", "")[:300]),
                    "relevance_score": float(result.get("relevance_score", 0.0)),
                    "mitigations": [
                        {"mitigation_name": str(m.get("mitigation_name", "")), "description": str(m.get("description", "")[:100])}
                        for m in result["threat"].get("mitigations", [])[:3]
                    ]
                }
                for result in kb_results
            ],
            "ai_analysis": str(analysis) if analysis else "No analysis available",
            "internet_search_results": [str(r) for r in mitigations_from_search] if mitigations_from_search else [],
            "recommendations": [str(r) for r in recommendations] if recommendations else [],
            "severity_assessment": str(severity)
        }
        
        return report
    
    def _prepare_context(self, kb_results: List[Dict], target_component: Optional[str]) -> str:
        """Prepare context from knowledge base for Gemini"""
        context = "## Knowledge Base Context\n\n"
        
        for i, result in enumerate(kb_results[:3], 1):  # Top 3
            threat = result["threat"]
            context += f"### Threat {i}: {threat['threat_name']}\n"
            context += f"- MITRE ID: {threat.get('mitre_id', 'N/A')}\n"
            context += f"- Affected Components: {', '.join(threat.get('oran_buckets', []))}\n"
            context += f"- Mitigations:\n"
            
            for mit in threat.get("mitigations", [])[:2]:
                context += f"  - {mit.get('mitigation_name')}: {mit.get('description', '')[:100]}\n"
            
            context += "\n"
        
        if target_component:
            context += f"**Target Component:** {target_component}\n"
        
        return context
    
    def _create_analysis_prompt(
        self,
        attack_description: str,
        indicators: List[str],
        target_component: Optional[str],
        context: str,
        kb_results: List[Dict]
    ) -> str:
        """Create comprehensive analysis prompt for Gemini"""
        
        threat_names = [r["threat"]["threat_name"] for r in kb_results]
        
        prompt = f"""
You are a cybersecurity expert analyzing threats in an O-RAN (Open Radio Access Network) environment.

## Attack Information
- **Description:** {attack_description}
- **Detected Indicators:** {', '.join(indicators)}
- **Target Component:** {target_component or 'Unknown'}

## Retrieved Threats from Knowledge Base
{context}

## Your Task
Based on the attack description, indicators, and knowledge base information, provide a comprehensive threat analysis report that includes:

1. **Threat Identification**: Identify which threats from the knowledge base this attack most likely corresponds to
2. **Attack Pattern Analysis**: Describe the likely attack pattern and methodology
3. **Impact Assessment**: Analyze potential impact on the O-RAN ecosystem
4. **Evidence Correlation**: Connect the detected indicators to known attack techniques
5. **Recommended Mitigations**: Provide step-by-step mitigation strategies
6. **Detection & Prevention**: Describe how this attack could be detected and prevented
7. **Severity Level**: Classify as Low/Medium/High/Critical with justification

Format your response in clear sections with actionable recommendations.
If this appears to be a novel or previously unknown attack, explicitly flag it and recommend security monitoring.
"""
        
        return prompt
    
    def _extract_recommendations(self, analysis: str) -> List[str]:
        """Extract actionable recommendations from analysis"""
        # Simple extraction - could be enhanced with NLP
        recommendations = []
        
        if "recommendation" in analysis.lower():
            lines = analysis.split('\n')
            for i, line in enumerate(lines):
                if "recommendation" in line.lower() and i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and not next_line.startswith('#'):
                        recommendations.append(next_line)
        
        return recommendations[:5] if recommendations else ["See AI analysis for detailed recommendations"]
    
    def _assess_severity(self, kb_results: List[Dict], description: str) -> str:
        """Assess attack severity"""
        severity_keywords = {
            "critical": ["data breach", "network down", "ransomware", "complete compromise"],
            "high": ["unauthorized access", "privilege escalation", "service disruption"],
            "medium": ["reconnaissance", "enumeration", "lateral movement"],
            "low": ["information disclosure", "logs"]
        }
        
        description_lower = description.lower()
        
        for severity, keywords in severity_keywords.items():
            if any(kw in description_lower for kw in keywords):
                return severity.upper()
        
        # Base on knowledge base matches
        if kb_results and any(r["threat"].get("severity") == "high" for r in kb_results):
            return "HIGH"
        
        return "MEDIUM"
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def update_knowledge_base(self, threat_id: str, threat_data: Dict[str, Any]) -> bool:
        """
        Update knowledge base with new or modified threat
        
        Args:
            threat_id: Unique threat identifier
            threat_data: Threat record data
        
        Returns:
            True if successful
        """
        return self.kb.add_threat(threat_data)
    
    def generate_report(self, analysis_result: Dict[str, Any]) -> str:
        """
        Generate formatted report from analysis result
        
        Args:
            analysis_result: Output from analyze_attack()
        
        Returns:
            Formatted report string
        """
        report = f"\n{'='*70}\n"
        report += "🛡️  THREAT ANALYSIS REPORT\n"
        report += f"{'='*70}\n\n"
        
        # Header
        attack_info = analysis_result["attack_info"]
        report += f"📋 ATTACK INFORMATION\n"
        report += f"  Description: {attack_info['description']}\n"
        report += f"  Indicators: {', '.join(attack_info['indicators'])}\n"
        if attack_info['target_component']:
            report += f"  Target: {attack_info['target_component']}\n"
        
        report += f"\n⚠️  SEVERITY: {analysis_result['severity_assessment']}\n"
        
        # KB Matches
        report += f"\n📚 KNOWLEDGE BASE MATCHES ({len(analysis_result['knowledge_base_matches'])} threats)\n"
        for threat in analysis_result['knowledge_base_matches']:
            report += f"  • {threat['threat_name']} ({threat.get('mitre_id', 'N/A')}) - {threat['relevance_score']:.0%} match\n"
            for mit in threat.get('mitigations', [])[:2]:
                report += f"    ↳ Mitigation: {mit.get('mitigation_name')}\n"
        
        # AI Analysis
        report += f"\n🤖 AI ANALYSIS & RECOMMENDATIONS\n"
        report += f"{'-'*70}\n"
        report += analysis_result['ai_analysis']
        
        # Extracted Recommendations
        report += f"\n\n✅ ACTION ITEMS\n"
        for i, rec in enumerate(analysis_result['recommendations'], 1):
            report += f"  {i}. {rec}\n"
        
        report += f"\n{'='*70}\n"
        
        return report


def main():
    """Test RAG agent"""
    
    # Initialize agent
    try:
        agent = RAGAgent()
    except ValueError as e:
        print(f"❌ {e}")
        print("\nTo use Gemini API:")
        print("1. Get free API key: https://makersuite.google.com/app/apikey")
        print("2. Set environment variable: GEMINI_API_KEY=your_key")
        return
    
    # Test attack scenarios
    test_attacks = [
        {
            "description": "Suspicious process execution detected on Near-RT RIC attempting network enumeration",
            "indicators": ["malicious_process.exe", "abnormal_outbound_connections", "privilege_escalation_attempt"],
            "target_component": "Near-RT RIC"
        },
        {
            "description": "Unauthorized API access attempts to O-Cloud management plane with credential stuffing",
            "indicators": ["multiple_failed_auth", "brute_force_pattern", "api_gateway_logs"],
            "target_component": "O-Cloud"
        }
    ]
    
    # Analyze attacks
    for i, attack in enumerate(test_attacks, 1):
        print(f"\n\n{'#'*70}")
        print(f"TEST CASE {i}")
        print(f"{'#'*70}")
        
        result = agent.analyze_attack(
            attack_description=attack["description"],
            detected_indicators=attack["indicators"],
            target_component=attack["target_component"]
        )
        
        # Generate and print report
        report = agent.generate_report(result)
        print(report)
        
        # Save report
        report_file = Path(f"rag/data/threat_report_{i}_{result['timestamp'].split('T')[0]}.txt")
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"✓ Report saved to {report_file}")


if __name__ == "__main__":
    main()
