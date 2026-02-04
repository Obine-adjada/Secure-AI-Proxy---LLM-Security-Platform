"""
Prompt Injection Detector
Détecte les tentatives d'injection de prompt malicieux
"""
import re
from typing import Dict, List, Tuple, Optional
from loguru import logger

class PromptInjectionDetector:
    """Détecte les injections de prompt"""
    
    def __init__(self, patterns: List[Dict]):
        """
        Args:
            patterns: Liste des patterns depuis config/patterns.yaml
        """
        self.patterns = patterns
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> List[Tuple[re.Pattern, str, str]]:
        """Compile les regex patterns pour performance"""
        compiled = []
        
        for pattern_dict in self.patterns:
            try:
                regex = re.compile(pattern_dict['pattern'], re.IGNORECASE)
                severity = pattern_dict.get('severity', 'medium')
                description = pattern_dict.get('description', 'Unknown threat')
                compiled.append((regex, severity, description))
            except re.error as e:
                logger.error(f"Invalid regex pattern: {pattern_dict['pattern']} - {e}")
        
        logger.info(f"Compiled {len(compiled)} injection patterns")
        return compiled
    
    def detect(self, prompt: str) -> Dict:
        """
        Détecte les injections dans un prompt
        Returns:
            {
                'detected': bool,
                'threats': [
                    {
                        'type': 'prompt_injection',
                        'severity': 'critical',
                        'description': '...',
                        'matched_pattern': '...',
                        'position': (start, end)
                    }
                ],
                'confidence': float,
                'risk_score': float
            }
        """
        threats = []
        
        for regex, severity, description in self.compiled_patterns:
            matches = list(regex.finditer(prompt))
            
            for match in matches:
                threats.append({
                    'type': 'prompt_injection',
                    'severity': severity,
                    'description': description,
                    'matched_text': match.group(0),
                    'matched_pattern': regex.pattern,
                    'position': match.span()
                })
        
        # Calcul du score de risque
        risk_score = self._calculate_risk_score(threats)
        confidence = min(risk_score / 10.0, 1.0)  # Normalisation 0-1
        
        return {
            'detected': len(threats) > 0,
            'threats': threats,
            'confidence': confidence,
            'risk_score': risk_score,
            'threat_count': len(threats)
        }
    
    def _calculate_risk_score(self, threats: List[Dict]) -> float:
        """
        Calcule un score de risque basé sur les menaces détectées
        Scores par sévérité:
        - critical: 10
        - high: 7
        - medium: 4
        - low: 2
        
        Le score est ensuite normalisé pour donner une confiance entre 0 et 1
        """
        severity_scores = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2
        }
        
        total_score = sum(
            severity_scores.get(threat['severity'], 2)
            for threat in threats
        )
        # Au moins une menace = confiance minimum de 0.5
        if total_score > 0:
            total_score = max(total_score, 5)
        
        return total_score