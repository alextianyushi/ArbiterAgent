from pydantic import BaseModel
from typing import List
from sqlalchemy import Table, Column, Integer, String, Text, MetaData, JSON
from sqlalchemy.ext.declarative import declarative_base

# Models for /process_findings endpoint
class Finding(BaseModel):
    """Individual finding data within a batch."""
    finding_id: str
    title: str
    description: str
    severity: str
    recommendation: str
    code_references: List[str]
    exploit_poc: str = None

class FindingsInput(BaseModel):
    """Request model for POST /process_findings."""
    project_id: str
    reported_by_agent: str = "api_user"
    findings: List[Finding]

class ProcessingResult(BaseModel):
    """Response model for POST /process_findings."""
    unique: int
    duplicated: int
    disputed: int

# Models for /statistics endpoint
class AgentStats(BaseModel):
    """Statistics for an agent's findings."""
    project_id: str
    agent_id: str
    unique_count: int
    duplicated_count: int
    disputed_count: int

Base = declarative_base()
metadata = MetaData()

def create_finding_table(table_name: str) -> Table:
    """Create a findings table with the specified name"""
    return Table(
        table_name, metadata,
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('reported_by_agent', String(255), nullable=False),
        Column('finding_id', String(100), nullable=False),
        Column('title', String(255), nullable=False),
        Column('description', Text, nullable=False),
        Column('severity', String(50), nullable=False),
        Column('recommendation', Text, nullable=True),
        Column('code_references', JSON, nullable=True),
        Column('exploit_poc', Text, nullable=True),
        Column('status', String(50), nullable=False, default='pending'),
        Column('details', Text, nullable=True)
    ) 