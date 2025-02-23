import os
from typing import Dict

def get_database_config() -> Dict:
    """Get database configuration from environment variables"""
    return {
        'dialect': os.getenv('DB_DIALECT', 'sqlite'),
        'driver': os.getenv('DB_DRIVER', 'sqlite'),
        'username': os.getenv('DB_USER'),
        'password': os.getenv('DB_PASSWORD'),
        'host': os.getenv('DB_HOST'),
        'port': os.getenv('DB_PORT'),
        'database': os.getenv('DB_NAME'),
        'sqlite_dir': os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    }

def get_database_url(config: Dict) -> str:
    """Generate database URL based on configuration"""
    if config['dialect'] == 'sqlite':
        os.makedirs(config['sqlite_dir'], exist_ok=True)
        return f"sqlite:///{os.path.join(config['sqlite_dir'], 'findings.db')}"
    elif config['dialect'] == 'mysql':
        return f"mysql+{config['driver']}://{config['username']}:{config['password']}@{config['host']}:{config['port']}/{config['database']}"
    elif config['dialect'] == 'postgresql':
        return f"postgresql://{config['username']}:{config['password']}@{config['host']}:{config['port']}/{config['database']}"
    else:
        raise ValueError(f"Unsupported database dialect: {config['dialect']}")

def get_engine_config(config: Dict) -> Dict:
    """Get database-specific engine configuration"""
    base_config = {
        'echo': False,
        'pool_size': 5,
        'max_overflow': 10,
        'pool_timeout': 30,
        'pool_recycle': 1800
    }
    
    if config['dialect'] == 'mysql':
        base_config.update({
            'connect_args': {'charset': 'utf8mb4'},
            'pool_pre_ping': True
        })
    elif config['dialect'] == 'postgresql':
        base_config.update({
            'pool_pre_ping': True
        })
        
    return base_config 