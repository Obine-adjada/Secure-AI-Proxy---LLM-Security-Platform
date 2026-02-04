import os
from typing import Dict, Any, Optional
from openai import OpenAI
from anthropic import Anthropic
from loguru import logger


class LLMClient:
    """
    Client unifié pour communiquer avec différents providers LLM
    Supporte OpenAI et Anthropic avec fallback en mode simulation
    """
    
    def __init__(self):
        self.openai_client = None
        self.anthropic_client = None
        self.simulation_mode = False
        
        self._init_openai()
        self._init_anthropic()
        
        if not self.openai_client and not self.anthropic_client:
            self.simulation_mode = True
            logger.warning("No API keys found - Running in SIMULATION MODE")
    
    def _init_openai(self):
        """Initialise le client OpenAI si API key disponible"""
        api_key = os.getenv('OPENAI_API_KEY')
        
        if api_key and api_key != 'your_openai_key_here' and len(api_key) > 20:
            try:
                self.openai_client = OpenAI(api_key=api_key)
                logger.info("OpenAI client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
        else:
            logger.warning("OPENAI_API_KEY not found or invalid - OpenAI calls will be simulated")
    
    def _init_anthropic(self):
        """Initialise le client Anthropic si API key disponible"""
        api_key = os.getenv('ANTHROPIC_API_KEY')
        
        if api_key and api_key != 'your_anthropic_key_here' and len(api_key) > 20:
            try:
                self.anthropic_client = Anthropic(api_key=api_key)
                logger.info("Anthropic client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Anthropic client: {e}")
        else:
            logger.warning("ANTHROPIC_API_KEY not found or invalid - Anthropic calls will be simulated")
    
    def chat_completion(
        self,
        prompt: str,
        model: str,
        provider: str,
        max_tokens: int = 1000,
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """
        Envoie une requête à un LLM et retourne la réponse
        Si pas d'API key, simule la réponse
        
        Args:
            prompt: Le prompt nettoyé à envoyer
            model: Nom du modèle
            provider: Provider à utiliser (openai, anthropic)
            max_tokens: Nombre maximum de tokens
            temperature: Température de génération
        
        Returns:
            {
                'success': bool,
                'response': str,
                'model': str,
                'provider': str,
                'tokens_used': int,
                'simulated': bool,
                'error': str (si échec)
            }
        """
        
        logger.info(
            f"Sending request to {provider}/{model} "
            f"(prompt length: {len(prompt)} chars)"
        )
        
        try:
            if provider.lower() == "openai":
                return self._openai_completion(prompt, model, max_tokens, temperature)
            
            elif provider.lower() == "anthropic":
                return self._anthropic_completion(prompt, model, max_tokens, temperature)
            
            else:
                return self._simulate_response(prompt, model, provider)
        
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            return self._simulate_response(prompt, model, provider, error=str(e))
    
    def _openai_completion(
        self,
        prompt: str,
        model: str,
        max_tokens: int,
        temperature: float
    ) -> Dict[str, Any]:
        """Appel à l'API OpenAI ou simulation"""
        
        if not self.openai_client:
            logger.info("Simulating OpenAI response (no valid API key)")
            return self._simulate_response(prompt, model, "openai")
        
        try:
            response = self.openai_client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            return {
                'success': True,
                'response': response.choices[0].message.content,
                'model': model,
                'provider': 'openai',
                'tokens_used': response.usage.total_tokens,
                'simulated': False
            }
        
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            logger.info("Falling back to simulation mode")
            return self._simulate_response(prompt, model, "openai", error=str(e))
    
    def _anthropic_completion(
        self,
        prompt: str,
        model: str,
        max_tokens: int,
        temperature: float
    ) -> Dict[str, Any]:
        """Appel à l'API Anthropic ou simulation"""
        
        if not self.anthropic_client:
            logger.info("Simulating Anthropic response (no valid API key)")
            return self._simulate_response(prompt, model, "anthropic")
        
        try:
            response = self.anthropic_client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            return {
                'success': True,
                'response': response.content[0].text,
                'model': model,
                'provider': 'anthropic',
                'tokens_used': response.usage.input_tokens + response.usage.output_tokens,
                'simulated': False
            }
        
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            logger.info("Falling back to simulation mode")
            return self._simulate_response(prompt, model, "anthropic", error=str(e))
    
    def _simulate_response(
        self,
        prompt: str,
        model: str,
        provider: str,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Génère une réponse simulée réaliste
        Utilisé quand pas d'API key ou en cas d'erreur
        """
        
        response_text = (
            f"This is a simulated response from {model} ({provider}). "
            f"Your prompt has been analyzed and processed securely by the AI Proxy. "
            f"In production, this would be a real response from the LLM API. "
            f"Prompt length: {len(prompt)} characters."
        )
        
        if error:
            response_text += f" Note: Real API call failed ({error[:50]}...), using simulation."
        
        return {
            'success': True,
            'response': response_text,
            'model': model,
            'provider': provider,
            'tokens_used': 50,
            'simulated': True
        }

# Instance globale
llm_client = LLMClient()