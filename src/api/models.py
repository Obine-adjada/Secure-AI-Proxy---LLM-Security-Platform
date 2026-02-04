from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class LLMRequest(BaseModel):
    """
    Modèle de requête vers un LLM
    Représente ce que l'utilisateur envoie au proxy
    """
    
    prompt: str = Field(
        ...,
        description="Le prompt à envoyer au LLM",
        min_length=1,
        max_length=50000
    )
    
    model: str = Field(
        default="gpt-3.5-turbo",
        description="Le modèle LLM à utiliser"
    )
    
    provider: str = Field(
        default="openai",
        description="Le provider LLM (openai, anthropic, etc.)"
    )
    
    user: str = Field(
        default="anonymous",
        description="Identifiant de l'utilisateur"
    )
    
    max_tokens: Optional[int] = Field(
        default=1000,
        description="Nombre maximum de tokens dans la réponse",
        ge=1,
        le=4000
    )
    
    temperature: Optional[float] = Field(
        default=0.7,
        description="Température pour la génération",
        ge=0.0,
        le=2.0
    )


class ThreatDetail(BaseModel):
    """Détail d'une menace détectée"""
    
    type: str
    severity: str
    description: str
    matched_text: str
    position: tuple


class SecurityAnalysis(BaseModel):
    """Résultat de l'analyse de sécurité"""
    
    request_id: str
    timestamp: str
    user: str
    original_prompt: str
    sanitized_prompt: str
    threats_detected: List[Dict[str, Any]]
    threat_count: int
    action: str
    blocked: bool
    analysis: Dict[str, Any]
    sanitization: Optional[List[Dict[str, Any]]] = None


class LLMResponse(BaseModel):
    """
    Réponse du proxy après traitement
    Ce que le proxy renvoie à l'utilisateur
    """
    
    request_id: str
    status: str
    blocked: bool
    action: str
    
    # Requête passée
    llm_response: Optional[str] = None
    model_used: Optional[str] = None
    
    # Requête bloquée
    block_reason: Optional[str] = None
    
    # Informations de sécurité
    security_analysis: Optional[Dict[str, Any]] = None
    threats_found: Optional[int] = None
    
    # Metadata
    processing_time: Optional[float] = None

class HealthCheckResponse(BaseModel):
    """Réponse du health check"""
    
    status: str
    version: str
    security_mode: str
    detectors_loaded: int