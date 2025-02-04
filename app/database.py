from sqlalchemy import create_engine, Table, Column, Integer, String, JSON, MetaData, inspect
from sqlalchemy.exc import IntegrityError
from typing import List, Dict

# Define the database URL using SQLite
DATABASE_URL = "sqlite:///findings.db"

# Create the database engine (disable SQL echo)
engine = create_engine(DATABASE_URL, echo=False)

# Initialize MetaData for dynamic table creation
metadata = MetaData()

class DatabaseError(Exception):
    """Base exception for database operations"""
    pass

def get_project_table(project_id: str):
    """
    Dynamically create or retrieve a table for a given project.
    
    :param project_id: The identifier of the project (used to form the table name)
    :return: SQLAlchemy Table object for the project
    """
    table_name = f"findings_{project_id}"
    inspector = inspect(engine)
    
    # Check if the table already exists in the database
    if not inspector.has_table(table_name):
        # Define the table structure
        project_table = Table(
            table_name, metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('reported_by_agent', String, nullable=False),
            Column('finding_id', String, nullable=False),
            Column('description', String, nullable=False),
            Column('severity', String, nullable=False),
            Column('recommendation', String, nullable=False),
            Column('code_reference', String, nullable=False),
            Column('metadata', JSON, nullable=True),
            Column('status', String, nullable=False, default='pending', server_default='pending')
        )
        # Create the table in the database
        metadata.create_all(engine, tables=[project_table])
    else:
        # If table exists, reflect its structure from the database
        project_table = Table(table_name, metadata, autoload_with=engine)
    
    return project_table

def insert_findings(project_id: str, agent_id: str, findings: List[Dict], metadata: Dict = None):
    """
    Insert findings into the project table.
    
    :param project_id: The identifier of the project
    :param agent_id: The identifier of the agent reporting the findings
    :param findings: List of finding dictionaries containing finding details
    :param metadata: Additional metadata for the findings
    :raises DatabaseError: If there's any error during database operations
    """
    if not project_id or not agent_id:
        raise DatabaseError("Project ID and Agent ID cannot be empty")
        
    required_fields = ['finding_id', 'description', 'severity', 'recommendation', 'code_reference']
    project_table = get_project_table(project_id)
    
    with engine.connect() as connection:
        for finding in findings:
            # Validate required fields
            missing_fields = [field for field in required_fields if field not in finding or not finding[field]]
            if missing_fields:
                raise DatabaseError(f"Missing required fields: {', '.join(missing_fields)}")
            
            try:
                insert_stmt = project_table.insert().values(
                    reported_by_agent=agent_id,
                    finding_id=finding["finding_id"],
                    description=finding["description"],
                    severity=finding["severity"],
                    recommendation=finding["recommendation"],
                    code_reference=finding["code_reference"],
                    metadata=metadata
                    # status will automatically be set to 'pending' by the database
                )
                
                connection.execute(insert_stmt)
                connection.commit()
                
            except Exception as e:
                connection.rollback()
                raise DatabaseError(f"Database error: {str(e)}")
