import uvicorn
from loguru import logger
from src.utils.config import config
from dotenv import load_dotenv

load_dotenv()

def main():
    """
    Point d'entrée de l'application Secure AI Proxy
    Lance le serveur FastAPI
    """
    
    proxy_config = config.proxy
    
    logger.info("Starting Secure AI Proxy")
    logger.info(f"Host: {proxy_config.host}")
    logger.info(f"Port: {proxy_config.port}")
    logger.info(f"Debug Mode: {proxy_config.debug}")
    logger.info(f"Security Mode: {config.security.mode}")
    
    uvicorn.run(
        "src.core.proxy:app",
        host=proxy_config.host,
        port=proxy_config.port,
        reload=proxy_config.debug,
        workers=1 if proxy_config.debug else proxy_config.workers
    )


if __name__ == "__main__":
    main()