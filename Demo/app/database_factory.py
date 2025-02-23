from typing import Dict, Any
from app.logger import setup_logging
from app.models import metadata, create_finding_table

logger = setup_logging()

class DatabaseFactory:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metadata = metadata
        
    def create_table(self, table_name: str):
        """Create a findings table with the specified name"""
        try:
            table = create_finding_table(table_name)
            logger.info(f"Successfully created table definition: {table_name}")
            return table
        except Exception as e:
            logger.error(f"Error creating table definition: {str(e)}")
            raise 