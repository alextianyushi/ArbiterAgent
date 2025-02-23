from sqlalchemy import create_engine, inspect, select, func, Table
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import QueuePool
from typing import List, Dict
from contextlib import contextmanager
from app.config import get_database_config, get_database_url, get_engine_config
from app.database_factory import DatabaseFactory
from app.logger import setup_logging

# Set up logging
logger = setup_logging()

# Initialize database configuration
db_config = get_database_config()
DATABASE_URL = get_database_url(db_config)
engine_config = get_engine_config(db_config)

# Create database engine
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    **engine_config
)

# Initialize database factory
db_factory = DatabaseFactory(db_config)

class DatabaseError(Exception):
    """Base exception for database operations"""
    pass

@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    Ensures proper handling of connections and transactions.
    This abstraction is database-agnostic and works with any SQLAlchemy supported database.
    """
    connection = engine.connect()
    try:
        yield connection
        connection.commit()
    except Exception as e:
        connection.rollback()
        logger.error(f"Database operation failed: {str(e)}")
        raise DatabaseError(f"Database operation failed: {str(e)}")
    finally:
        connection.close()

def get_project_table(project_id: str):
    """
    Dynamically create or retrieve a table for a given project.
    Uses DatabaseFactory to create database-specific table structures.
    
    :param project_id: The identifier of the project (used to form the table name)
    :return: SQLAlchemy Table object for the project
    :raises DatabaseError: If there's an error creating or retrieving the table
    """
    try:
        table_name = f"findings_{project_id}"
        inspector = inspect(engine)
        
        if not inspector.has_table(table_name):
            project_table = db_factory.create_table(table_name)
            project_table.create(engine)
            logger.info(f"Created new table: {table_name}")
        else:
            # If table exists, reflect its structure from the database
            project_table = Table(table_name, db_factory.metadata, autoload_with=engine, extend_existing=True)
            logger.debug(f"Using existing table: {table_name}")
        
        return project_table
    except Exception as e:
        logger.error(f"Error creating/retrieving project table: {str(e)}")
        raise DatabaseError(f"Error creating/retrieving project table: {str(e)}")

def insert_findings(project_id: str, agent_id: str, findings: List[Dict]):
    """
    Insert findings into the project table.
    Uses batch insert strategy appropriate for the current database.
    
    :param project_id: The identifier of the project
    :param agent_id: The identifier of the agent reporting the findings
    :param findings: List of finding dictionaries containing finding details
    :raises DatabaseError: If there's any error during database operations
    """
    if not project_id or not agent_id:
        raise DatabaseError("Project ID and Agent ID cannot be empty")
        
    required_fields = ['finding_id', 'title', 'description', 'severity']
    project_table = get_project_table(project_id)
    
    with get_db_connection() as connection:
        try:
            # Prepare batch insert data
            insert_data = []
            for finding in findings:
                missing_fields = [field for field in required_fields if field not in finding or not finding[field]]
                if missing_fields:
                    raise DatabaseError(f"Missing required fields: {', '.join(missing_fields)}")
                
                # Validate severity enum
                if finding['severity'] not in ['Low', 'Medium', 'High']:
                    raise DatabaseError(f"Invalid severity value: {finding['severity']}. Must be one of: Low, Medium, High")
                
                # Convert code_references to string for SQLite if needed
                code_refs = finding.get('code_references', [])
                if db_config['dialect'] == 'sqlite' and isinstance(code_refs, list):
                    import json
                    code_refs = json.dumps(code_refs)
                
                insert_data.append({
                    'reported_by_agent': agent_id,
                    'finding_id': finding["finding_id"],
                    'title': finding["title"],
                    'description': finding["description"],
                    'severity': finding["severity"],
                    'recommendation': finding.get("recommendation"),
                    'code_references': code_refs,
                    'exploit_poc': finding.get("exploit_poc"),
                    'status': 'pending'
                })
            
            # Use bulk insert for better performance
            connection.execute(project_table.insert(), insert_data)
            connection.commit()
            logger.info(f"Successfully inserted {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Error inserting findings: {str(e)}")
            raise DatabaseError(f"Error inserting findings: {str(e)}")
