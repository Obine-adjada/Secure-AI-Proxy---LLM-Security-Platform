import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from loguru import logger
from src.detectors.injection import PromptInjectionDetector
from src.detectors.dlp import DLPDetector
from src.detectors.jailbreak import JailbreakDetector
from src.utils.config import config


class SecurityAnalysisEngine:
    """
    Moteur d'analyse de sécurité
    Coordonne tous les détecteurs et prend les décisions de sécurité
    """
    def __init__(self):
        patterns = config.patterns
        
        self.injection_detector = PromptInjectionDetector(
            patterns.get('prompt_injection', [])
        )
        self.dlp_detector = DLPDetector(
            patterns.get('data_leak', [])
        )
        self.jailbreak_detector = JailbreakDetector(
            patterns.get('jailbreak', [])
        )
        
        self.security_config = config.security
        
        logger.info("Security Analysis Engine initialized")
    
    def analyze(self, prompt: str, user: str = "anonymous") -> Dict[str, Any]:
        """
        Analyse complète d'un prompt
        Args:
            prompt: Le texte à analyser
            user: Identifiant de l'utilisateur
        Returns:
            Dictionnaire contenant:
            - request_id: ID unique de la requête
            - timestamp: Horodatage de l'analyse
            - user: Utilisateur
            - original_prompt: Prompt original
            - sanitized_prompt: Prompt après sanitization (si applicable)
            - threats_detected: Liste des menaces détectées
            - action: Action recommandée (allow/block/sanitize)
            - blocked: Boolean indiquant si bloqué
            - analysis: Détails de l'analyse par détecteur
        """
        
        request_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        
        logger.info(f"[{request_id}] Starting security analysis for user: {user}")
        
        injection_result = self.injection_detector.detect(prompt)
        jailbreak_result = self.jailbreak_detector.detect(prompt)
        dlp_result = self.dlp_detector.detect(prompt)
        
        all_threats = []
        
        if injection_result['detected']:
            all_threats.extend(injection_result['threats'])
            logger.warning(
                f"[{request_id}] Prompt injection detected: "
                f"{injection_result['threat_count']} threats found"
            )
        
        if jailbreak_result['detected']:
            all_threats.extend(jailbreak_result['threats'])
            logger.warning(
                f"[{request_id}] Jailbreak attempt detected: "
                f"{jailbreak_result['threat_count']} threats found"
            )
        
        if dlp_result['detected']:
            all_threats.extend(dlp_result['leaks'])
            logger.warning(
                f"[{request_id}] Data leak detected: "
                f"{dlp_result['leak_count']} sensitive items found"
            )
        
        decision = self._make_decision(
            injection_result,
            jailbreak_result,
            dlp_result
        )
        
        sanitized_prompt = prompt
        sanitization_log = []
        
        if decision['action'] == 'sanitize':
            sanitized_prompt, sanitization_log = self.dlp_detector.sanitize(prompt)
            logger.info(
                f"[{request_id}] Prompt sanitized: "
                f"{len(sanitization_log)} items removed"
            )
        
        result = {
            'request_id': request_id,
            'timestamp': timestamp,
            'user': user,
            'original_prompt': prompt,
            'sanitized_prompt': sanitized_prompt,
            'threats_detected': all_threats,
            'threat_count': len(all_threats),
            'action': decision['action'],
            'blocked': decision['blocked'],
            'analysis': {
                'prompt_injection': injection_result,
                'jailbreak': jailbreak_result,
                'data_leak': dlp_result
            },
            'sanitization': sanitization_log if sanitization_log else None
        }
        
        logger.info(
            f"[{request_id}] Analysis complete: "
            f"Action={decision['action']}, Threats={len(all_threats)}"
        )
        
        return result
    
    def _make_decision(
        self,
        injection_result: Dict,
        jailbreak_result: Dict,
        dlp_result: Dict
    ) -> Dict[str, Any]:
        """
        Prend la décision finale basée sur les résultats des détecteurs
        Returns:
            {
                'action': 'allow' | 'block' | 'sanitize',
                'blocked': bool,
                'reason': str
            }
        """
        
        mode = self.security_config.mode
        actions = self.security_config.actions
        thresholds = self.security_config.thresholds
        
        # Mode dry-run 
        if mode == "dry-run":
            return {
                'action': 'allow',
                'blocked': False,
                'reason': 'Dry-run mode: no enforcement'
            }
        
        if injection_result['detected']:
            confidence = injection_result['confidence']
            threshold = thresholds.get('injection_confidence', 0.7)
            
            logger.debug(
                f"Injection confidence: {confidence:.2f}, threshold: {threshold}"
            )
            
            if confidence >= threshold:
                configured_action = actions.get('prompt_injection', 'block')
                
                if mode == "enforce" and configured_action == "block":
                    return {
                        'action': 'block',
                        'blocked': True,
                        'reason': f'Prompt injection detected (confidence: {confidence:.2f})'
                    }
                elif mode == "monitor":
                    return {
                        'action': 'allow',
                        'blocked': False,
                        'reason': 'Monitor mode: injection detected but allowed'
                    }
            else:
                logger.debug(
                    f"Injection below threshold, not blocking"
                )
        if jailbreak_result['detected']:
            confidence = jailbreak_result['confidence']
            threshold = thresholds.get('jailbreak_confidence', 0.75)
            
            logger.debug(
                f"Jailbreak confidence: {confidence:.2f}, threshold: {threshold}"
            )
            
            if confidence >= threshold:
                configured_action = actions.get('jailbreak', 'block')
                
                if mode == "enforce" and configured_action == "block":
                    return {
                        'action': 'block',
                        'blocked': True,
                        'reason': f'Jailbreak attempt detected (confidence: {confidence:.2f})'
                    }
                elif mode == "monitor":
                    return {
                        'action': 'allow',
                        'blocked': False,
                        'reason': 'Monitor mode: jailbreak detected but allowed'
                    }
            else:
                logger.debug(
                    f"Jailbreak below threshold, not blocking"
                )
        if dlp_result['detected']:
            confidence = dlp_result['confidence']
            threshold = thresholds.get('dlp_confidence', 0.8)
            
            logger.debug(
                f"DLP confidence: {confidence:.2f}, threshold: {threshold}"
            )
            
            if confidence >= threshold:
                configured_action = actions.get('data_leak', 'sanitize')
                
                if mode == "enforce":
                    if configured_action == "block":
                        return {
                            'action': 'block',
                            'blocked': True,
                            'reason': f'Sensitive data detected (confidence: {confidence:.2f})'
                        }
                    else:
                        return {
                            'action': 'sanitize',
                            'blocked': False,
                            'reason': f'Sensitive data detected and sanitized (confidence: {confidence:.2f})'
                        }
                elif mode == "monitor":
                    return {
                        'action': 'allow',
                        'blocked': False,
                        'reason': 'Monitor mode: data leak detected but allowed'
                    }
            else:
                logger.debug(
                    f"DLP below threshold, not sanitizing"
                )
        
        # Aucune menace détectée ou toutes sous les seuils
        return {
            'action': 'allow',
            'blocked': False,
            'reason': 'No threats detected above thresholds'
        }