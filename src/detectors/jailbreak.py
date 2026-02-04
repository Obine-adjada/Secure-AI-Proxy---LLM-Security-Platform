"""
Jailbreak Detector
Détecte les tentatives de jailbreak (DAN, role-playing, etc.)
"""
import re
from typing import Dict, List, Tuple
from loguru import logger


class JailbreakDetector:
    """Détecte les tentatives de jailbreak"""
    
    def __init__(self, patterns: List[Dict]):
        """
        Args:
            patterns: Liste des patterns jailbreak depuis config/patterns.yaml
        """
        self.patterns = patterns
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> List[Tuple[re.Pattern, str, str]]:
        """Compile les regex patterns jailbreak"""
        compiled = []
        
        for pattern_dict in self.patterns:
            try:
                regex = re.compile(pattern_dict['pattern'], re.IGNORECASE)
                severity = pattern_dict.get('severity', 'medium')
                description = pattern_dict.get('description', 'Jailbreak attempt')
                compiled.append((regex, severity, description))
            except re.error as e:
                logger.error(f"Invalid jailbreak pattern: {pattern_dict['pattern']} - {e}")
        
        logger.info(f" Compiled {len(compiled)} jailbreak patterns")
        return compiled
    
    def detect(self, prompt: str) -> Dict:
        """
        Détecte les jailbreaks dans un prompt
        Returns:
            {
                'detected': bool,
                'threats': [...],
                'confidence': float,
                'risk_score': float
            }
        """
        threats = []
        
        for regex, severity, description in self.compiled_patterns:
            matches = list(regex.finditer(prompt))
            
            for match in matches:
                threats.append({
                    'type': 'jailbreak',
                    'severity': severity,
                    'description': description,
                    'matched_text': match.group(0),
                    'matched_pattern': regex.pattern,
                    'position': match.span()
                })
        
        risk_score = self._calculate_risk_score(threats)
        confidence = min(risk_score / 10.0, 1.0)
        
        return {
            'detected': len(threats) > 0,
            'threats': threats,
            'confidence': confidence,
            'risk_score': risk_score,
            'threat_count': len(threats)
        }
    
    def _calculate_risk_score(self, threats: List[Dict]) -> float:
        """Calcule le score de risque"""
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