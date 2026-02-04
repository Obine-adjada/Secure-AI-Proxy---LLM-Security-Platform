"""
Configuration Manager pour Secure AI Proxy
Charge et valide les configurations depuis config.yaml
"""
import yaml
from pathlib import Path
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from loguru import logger


class ProxyConfig(BaseModel):
    """Configuration du proxy"""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True
    workers: int = 4


class LLMProviderConfig(BaseModel):
    """Configuration d'un provider LLM"""
    enabled: bool = True
    api_base: str
    models: List[str]


class SecurityConfig(BaseModel):
    """Configuration de sécurité"""
    mode: str = "enforce"  # enforce | monitor | dry-run
    actions: Dict[str, str] = {
        "prompt_injection": "block",
        "data_leak": "sanitize",
        "jailbreak": "block"
    }
    thresholds: Dict[str, float] = {
        "injection_confidence": 0.7,
        "dlp_confidence": 0.8,
        "jailbreak_confidence": 0.75
    }


class LoggingConfig(BaseModel):
    """Configuration du logging"""
    level: str = "INFO"
    elasticsearch: Dict[str, Any] = {
        "enabled": False,
        "host": "localhost",
        "port": 9200,
        "index": "ai-proxy-logs"
    }
    redis: Dict[str, Any] = {
        "enabled": False,
        "host": "localhost",
        "port": 6379,
        "db": 0
    }


class Config:
    """Classe principale de configuration"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self._patterns: Dict[str, Any] = {}
        
        self.load_config()
        self.load_patterns()
    
    def load_config(self):
        """Charge la configuration depuis config.yaml"""
        try:
            if not self.config_path.exists():
                logger.warning(f"Config file not found: {self.config_path}")
                self._use_defaults()
                return
            
            with open(self.config_path, 'r') as f:
                self._config = yaml.safe_load(f)
            
            logger.info(f" Configuration loaded from {self.config_path}")
        
        except Exception as e:
            logger.error(f" Error loading config: {e}")
            self._use_defaults()
    
    def load_patterns(self):
        """Charge les patterns de détection depuis patterns.yaml"""
        patterns_path = Path("config/patterns.yaml")
        
        try:
            if not patterns_path.exists():
                logger.warning(f"Patterns file not found: {patterns_path}")
                return
            
            with open(patterns_path, 'r') as f:
                self._patterns = yaml.safe_load(f)
            
            logger.info(f"Detection patterns loaded: {len(self._patterns)} categories")
        
        except Exception as e:
            logger.error(f" Error loading patterns: {e}")
    
    def _use_defaults(self):
        """Utilise la configuration par défaut"""
        self._config = {
            "proxy": {"host": "0.0.0.0", "port": 8000, "debug": True},
            "security": {
                "mode": "enforce",
                "actions": {
                    "prompt_injection": "block",
                    "data_leak": "sanitize",
                    "jailbreak": "block"
                }
            }
        }
    
    @property
    def proxy(self) -> ProxyConfig:
        """Retourne la config du proxy"""
        return ProxyConfig(**self._config.get("proxy", {}))
    
    @property
    def security(self) -> SecurityConfig:
        """Retourne la config de sécurité"""
        return SecurityConfig(**self._config.get("security", {}))
    
    @property
    def logging_config(self) -> LoggingConfig:
        """Retourne la config de logging"""
        return LoggingConfig(**self._config.get("logging", {}))
    
    @property
    def patterns(self) -> Dict[str, Any]:
        """Retourne les patterns de détection"""
        return self._patterns
    
    def get_llm_provider(self, provider: str) -> LLMProviderConfig:
        """Retourne la config d'un provider LLM"""
        providers = self._config.get("llm_providers", {})
        if provider not in providers:
            raise ValueError(f"Unknown provider: {provider}")
        return LLMProviderConfig(**providers[provider])

config = Config()