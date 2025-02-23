from fastapi import APIRouter, HTTPException, Query
from app.models import FindingsInput, ProcessingResult, AgentStats
from app.database import get_project_table, get_db_connection, DatabaseError
from app.deduplication import check_duplicates
from app.evaluation import evaluate_findings
from pydantic import BaseModel, Field
from sqlalchemy import select, text, func
from app.logger import setup_logging
from typing import List
import json

# Set up logging
logger = setup_logging()

# Create router with prefix /api
router = APIRouter(
    prefix="/api",
    tags=["findings"]
)

@router.get("/statistics", response_model=List[AgentStats])
async def get_statistics(project_id: str = Query(None, description="Optional project ID to filter statistics")) -> List[AgentStats]:
    """
    Get statistics for findings.
    If project_id is provided, returns statistics only for that project.
    Otherwise returns statistics for all projects.
    
    Args:
        project_id: Optional project identifier to filter results
        
    Returns:
        List[AgentStats]: List of statistics for each project-agent combination
    """
    try:
        with get_db_connection() as connection:
            try:
                stats = []
                
                if project_id:
                    # Get statistics for specific project
                    logger.info(f"Getting statistics for project: {project_id}")
                    project_table = get_project_table(project_id)
                    
                    agent_results = connection.execute(
                        select(
                            project_table.c.reported_by_agent,
                            func.count(project_table.c.id).filter(project_table.c.status == 'unique').label('unique_count'),
                            func.count(project_table.c.id).filter(project_table.c.status == 'duplicated').label('duplicated_count'),
                            func.count(project_table.c.id).filter(project_table.c.status == 'disputed').label('disputed_count')
                        ).group_by(project_table.c.reported_by_agent)
                    ).fetchall()
                    
                    for result in agent_results:
                        stats.append(AgentStats(
                            project_id=project_id,
                            agent_id=result.reported_by_agent,
                            unique_count=result.unique_count,
                            duplicated_count=result.duplicated_count,
                            disputed_count=result.disputed_count
                        ))
                else:
                    # Get statistics for all projects
                    logger.info("Getting statistics for all projects")
                    tables = connection.execute(
                        text("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'findings_%'")
                    ).fetchall()
                    
                    for (table_name,) in tables:
                        current_project_id = table_name.replace('findings_', '')
                        project_table = get_project_table(current_project_id)
                        
                        agent_results = connection.execute(
                            select(
                                project_table.c.reported_by_agent,
                                func.count(project_table.c.id).filter(project_table.c.status == 'unique').label('unique_count'),
                                func.count(project_table.c.id).filter(project_table.c.status == 'duplicated').label('duplicated_count'),
                                func.count(project_table.c.id).filter(project_table.c.status == 'disputed').label('disputed_count')
                            ).group_by(project_table.c.reported_by_agent)
                        ).fetchall()
                        
                        for result in agent_results:
                            stats.append(AgentStats(
                                project_id=current_project_id,
                                agent_id=result.reported_by_agent,
                                unique_count=result.unique_count,
                                duplicated_count=result.duplicated_count,
                                disputed_count=result.disputed_count
                            ))
                
                return stats
                
            except Exception as e:
                logger.error(f"Database operation failed: {str(e)}")
                raise DatabaseError(f"Operation failed: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/process_findings", response_model=ProcessingResult)
async def process_findings(input_data: FindingsInput) -> ProcessingResult:
    """
    Process security findings:
    1. Store findings in database
    2. Perform deduplication
    3. Evaluate finding quality
    
    Args:
        input_data: Contains project_id, reported_by_agent and list of findings
        
    Returns:
        ProcessingResult: Contains counts of unique, duplicated and disputed findings
    """
    try:
        project_id = input_data.project_id
        logger.info(f"Processing new findings batch with project_id: {project_id}")
        
        project_table = get_project_table(project_id)
        current_batch_ids = []
        
        with get_db_connection() as connection:
            try:
                # Store findings
                for finding in input_data.findings:
                    # Convert code_references to JSON string for SQLite
                    code_refs = json.dumps(finding.code_references) if finding.code_references else '[]'
                    
                    insert_stmt = project_table.insert().values(
                        reported_by_agent=input_data.reported_by_agent,
                        finding_id=finding.finding_id,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity,
                        recommendation=finding.recommendation,
                        code_references=code_refs,
                        exploit_poc=finding.exploit_poc,
                        status='pending'
                    )
                    result = connection.execute(insert_stmt)
                    current_batch_ids.append(result.inserted_primary_key[0])
                
                connection.commit()
                
                # Deduplication and evaluation
                check_duplicates(project_id, current_batch_ids)
                evaluate_findings(project_id, current_batch_ids)
                
                # Get results
                result = connection.execute(
                    select(project_table).where(
                        project_table.c.id.in_(current_batch_ids),
                        project_table.c.status == 'unique'
                    )
                )
                unique_count = len(result.fetchall())
                
                result = connection.execute(
                    select(project_table).where(
                        project_table.c.id.in_(current_batch_ids),
                        project_table.c.status == 'duplicated'
                    )
                )
                duplicated_count = len(result.fetchall())
                
                result = connection.execute(
                    select(project_table).where(
                        project_table.c.id.in_(current_batch_ids),
                        project_table.c.status == 'disputed'
                    )
                )
                disputed_count = len(result.fetchall())
                
                return ProcessingResult(
                    unique=unique_count,
                    duplicated=duplicated_count,
                    disputed=disputed_count
                )
                
            except Exception as e:
                logger.error(f"Error during processing: {str(e)}")
                raise DatabaseError(f"Operation failed: {str(e)}")
                
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 