import sys
import json
from pathlib import Path
from loguru import logger
from datetime import datetime
from typing import Dict, Any, Optional


class SecurityLogger:
    """
    Logger spécialisé pour les événements de sécurité
    Écrit les logs en JSON pour faciliter l'ingestion par Filebeat
    """
    
    def __init__(self, log_dir: str = "data/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self._setup_logger()
    
    def _setup_logger(self):
        """Configure loguru avec sortie console et fichiers"""
        
        logger.remove()
        
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
            level="INFO",
            colorize=True
        )
        
        logger.add(
            self.log_dir / "proxy_{time:YYYY-MM-DD}.log",
            rotation="00:00",
            retention="30 days",
            compression="zip",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
            level="DEBUG"
        )
    
    def log_security_event(self, event_data: Dict[str, Any]):
        """
        Log un événement de sécurité en JSON pour Filebeat
        Écrit dans un fichier séparé au format JSON lines
        """
        
        json_log_file = self.log_dir / f"security_{datetime.utcnow().strftime('%Y-%m-%d')}.json"
        
        if 'timestamp' not in event_data:
            event_data['timestamp'] = datetime.utcnow().isoformat()
        
        try:
            with open(json_log_file, 'a') as f:
                f.write(json.dumps(event_data) + '\n')
        except Exception as e:
            logger.error(f"Failed to write JSON log: {e}")
    
    def log_request(
        self,
        request_id: str,
        user: str,
        prompt: str,
        model: str,
        provider: str
    ):
        """Log une requête LLM"""
        logger.info(
            f"[{request_id}] Request from {user} to {provider}/{model} "
            f"(prompt length: {len(prompt)} chars)"
        )
    
    def log_detection(
        self,
        request_id: str,
        threat_type: str,
        severity: str,
        details: Dict[str, Any],
        action: str
    ):
        """Log une détection de menace"""
        logger.bind(SECURITY=True).warning(
            f"[{request_id}] THREAT DETECTED | "
            f"Type: {threat_type} | "
            f"Severity: {severity} | "
            f"Action: {action} | "
            f"Details: {details}"
        )
    
    def log_block(
        self,
        request_id: str,
        reason: str,
        threat_type: str
    ):
        """Log un blocage"""
        logger.bind(SECURITY=True).error(
            f"[{request_id}] REQUEST BLOCKED | "
            f"Reason: {reason} | "
            f"Threat: {threat_type}"
        )
    
    def log_sanitization(
        self,
        request_id: str,
        sanitized_count: int,
        data_types: list
    ):
        """Log une sanitization"""
        logger.bind(SECURITY=True).warning(
            f"[{request_id}] DATA SANITIZED | "
            f"Items removed: {sanitized_count} | "
            f"Types: {', '.join(data_types)}"
        )
    
    def log_response(
        self,
        request_id: str,
        status: str,
        response_time: float
    ):
        """Log une réponse"""
        logger.info(
            f"[{request_id}] Response sent | "
            f"Status: {status} | "
            f"Time: {response_time:.2f}s"
        )

# Instance globale
security_logger = SecurityLogger()