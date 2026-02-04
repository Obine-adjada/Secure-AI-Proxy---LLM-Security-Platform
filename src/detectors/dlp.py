"""
Data Leak Prevention (DLP) Detector
Détecte et extrait les données sensibles (PII, secrets, etc.)
"""
import re
from typing import Dict, List, Tuple
from loguru import logger

class DLPDetector:
    """Détecteur de fuites de données sensibles"""
    
    def __init__(self, patterns: List[Dict]):
        """
        Args:
            patterns: Liste des patterns DLP depuis config/patterns.yaml
        """
        self.patterns = patterns
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> List[Tuple[re.Pattern, str, str, str]]:
        """Compile les regex patterns DLP"""
        compiled = []
        
        for pattern_dict in self.patterns:
            try:
                regex = re.compile(pattern_dict['pattern'])
                severity = pattern_dict.get('severity', 'medium')
                description = pattern_dict.get('description', 'Sensitive data')
                data_type = pattern_dict.get('type', 'unknown')
                compiled.append((regex, severity, description, data_type))
            except re.error as e:
                logger.error(f"Invalid DLP pattern: {pattern_dict['pattern']} - {e}")
        
        logger.info(f" Compiled {len(compiled)} DLP patterns")
        return compiled
    
    def detect(self, text: str) -> Dict:
        """
        Détecte les données sensibles dans le texte
        Returns:
            {
                'detected': bool,
                'leaks': [
                    {
                        'type': 'email',
                        'severity': 'high',
                        'description': '...',
                        'matched_text': '...',
                        'position': (start, end)
                    }
                ],
                'confidence': float,
                'data_types': ['email', 'phone', ...]
            }
        """
        leaks = []
        data_types = set()
        
        for regex, severity, description, data_type in self.compiled_patterns:
            matches = list(regex.finditer(text))
            
            for match in matches:
                leaks.append({
                    'type': data_type,
                    'severity': severity,
                    'description': description,
                    'matched_text': match.group(0),
                    'matched_pattern': regex.pattern,
                    'position': match.span()
                })
                data_types.add(data_type)
        
        confidence = min(len(leaks) / 5.0, 1.0)  
        
        return {
            'detected': len(leaks) > 0,
            'leaks': leaks,
            'confidence': confidence,
            'leak_count': len(leaks),
            'data_types': sorted(list(data_types))
        }
    
    def sanitize(self, text: str) -> Tuple[str, List[Dict]]:
        """
        Retire les données sensibles du texte
        Returns:
            (sanitized_text, removed_items)
        """
        sanitized_text = text
        removed_items = []
        
        for regex, severity, description, data_type in self.compiled_patterns:
            matches = list(regex.finditer(sanitized_text))
            
            for match in reversed(matches):  # Reverse pour garder les positions valides
                start, end = match.span()
                matched_value = match.group(0)
                
                # Remplacement par [REDACTED_TYPE]
                replacement = f"[REDACTED_{data_type.upper()}]"
                sanitized_text = sanitized_text[:start] + replacement + sanitized_text[end:]
                
                removed_items.append({
                    'type': data_type,
                    'severity': severity,
                    'original_value': matched_value,
                    'replacement': replacement
                })
        
        return sanitized_text, removed_items