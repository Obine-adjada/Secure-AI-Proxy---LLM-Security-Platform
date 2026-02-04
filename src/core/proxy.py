import time
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from src.api.models import LLMRequest, LLMResponse, HealthCheckResponse
from src.core.engine import SecurityAnalysisEngine
from src.utils.config import config


app = FastAPI(
    title="Secure AI Proxy",
    description="Proxy de sécurité pour protéger les intégrations LLM",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security_engine = SecurityAnalysisEngine()

@app.get("/", response_model=HealthCheckResponse)
async def root():
    """
    Endpoint de santé du service
    Vérifie que le proxy fonctionne correctement
    """
    return HealthCheckResponse(
        status="operational",
        version="1.0.0",
        security_mode=config.security.mode,
        detectors_loaded=3
    )


@app.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """
    Health check endpoint pour monitoring
    """
    return HealthCheckResponse(
        status="healthy",
        version="1.0.0",
        security_mode=config.security.mode,
        detectors_loaded=3
    )


@app.post("/v1/chat/completions", response_model=LLMResponse)
async def proxy_llm_request(request: LLMRequest):
    """
    Endpoint principal du proxy
    Args:
        request: LLMRequest contenant le prompt et les paramètres
    Returns:
        LLMResponse avec le résultat ou le blocage
    """
    
    start_time = time.time()
    
    logger.info(
        f"Received request from user: {request.user}, "
        f"model: {request.model}, provider: {request.provider}"
    )
    
    try:
        analysis = security_engine.analyze(
            prompt=request.prompt,
            user=request.user
        )
    except Exception as e:
        logger.error(f"Security analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security analysis failed"
        )
    
    processing_time = time.time() - start_time
    
    if analysis['blocked']:
        logger.warning(
            f"[{analysis['request_id']}] Request blocked: "
            f"{analysis['action']}, threats: {analysis['threat_count']}"
        )
        
        # Log événement de sécurité
        from src.utils.logger import security_logger
        
        security_logger.log_security_event({
            "event_type": "llm_request",
            "request_id": analysis['request_id'],
            "username": request.user,
            "provider": request.provider,
            "model": request.model,
            "prompt_length": len(request.prompt),
            "action": analysis['action'],
            "blocked": True,
            "threat_count": analysis['threat_count'],
            "threats": analysis['threats_detected'],
            "processing_time": processing_time
        })

        return LLMResponse(
            request_id=analysis['request_id'],
            status="blocked",
            blocked=True,
            action=analysis['action'],
            block_reason=f"Security threat detected: {analysis['threat_count']} threats found",
            security_analysis=analysis,
            threats_found=analysis['threat_count'],
            processing_time=processing_time
        )
    
    if analysis['action'] == 'sanitize':
        logger.info(
            f"[{analysis['request_id']}] Request sanitized, "
            f"proceeding with cleaned prompt"
        )
        prompt_to_use = analysis['sanitized_prompt']
    else:
        prompt_to_use = request.prompt
    
    from src.utils.llm_client import llm_client
    
    llm_result = llm_client.chat_completion(
        prompt=prompt_to_use,
        model=request.model,
        provider=request.provider,
        max_tokens=request.max_tokens,
        temperature=request.temperature
    )
    
    processing_time = time.time() - start_time
    
    if not llm_result['success']:
        logger.error(
            f"[{analysis['request_id']}] LLM API call failed: "
            f"{llm_result.get('error', 'Unknown error')}"
        )
        
        return LLMResponse(
            request_id=analysis['request_id'],
            status="error",
            blocked=False,
            action=analysis['action'],
            block_reason=f"LLM API error: {llm_result.get('error')}",
            security_analysis=analysis,
            threats_found=analysis['threat_count'],
            processing_time=processing_time
        )
    
    logger.info(
        f"[{analysis['request_id']}] LLM response received "
        f"(tokens: {llm_result.get('tokens_used', 0)})"
    )
    
    # Log événement de sécurité en JSON pour Filebeat
    from src.utils.logger import security_logger
    
    security_logger.log_security_event({
        "event_type": "llm_request",
        "request_id": analysis['request_id'],
        "username": request.user,
        "provider": request.provider,
        "model": request.model,
        "prompt_length": len(request.prompt),
        "action": analysis['action'],
        "blocked": analysis['blocked'],
        "threat_count": analysis['threat_count'],
        "threats": analysis['threats_detected'],
        "processing_time": processing_time,
        "has_llm_response": llm_result['success'] if 'llm_result' in locals() else False
    })

    return LLMResponse(
        request_id=analysis['request_id'],
        status="success",
        blocked=False,
        action=analysis['action'],
        llm_response=llm_result['response'],
        model_used=llm_result['model'],
        security_analysis=analysis,
        threats_found=analysis['threat_count'],
        processing_time=processing_time
    )

@app.post("/v1/analyze", response_model=dict)
async def analyze_only(request: LLMRequest):
    """
    Endpoint pour analyser un prompt sans l'envoyer au LLM
    Args:
        request: LLMRequest contenant le prompt
    Returns:
        Résultats complets de l'analyse de sécurité
    """
    
    try:
        analysis = security_engine.analyze(
            prompt=request.prompt,
            user=request.user
        )
        return analysis
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )