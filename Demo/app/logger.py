import logging
import os
import sys
from logging.handlers import RotatingFileHandler

def setup_logging():
    """
    Set up logging configuration for the entire application
    """
    # Get log level from environment variable
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            # Console handler with detailed formatting
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Add file handler if not in production
    if os.getenv('ENVIRONMENT') != 'production':
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'app.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logging.getLogger().addHandler(file_handler)
    
    # Set log levels for third-party libraries
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
    
    logger = logging.getLogger('app')
    logger.info('Logging setup completed')
    return logger 