import os
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from typing import Tuple, List
from dotenv import load_dotenv
from app.database import get_project_table, get_db_connection, DatabaseError
import logging
from retrying import retry
from anthropic import Anthropic

# Load environment variables from .env file
load_dotenv()

# Get configuration from environment variables
EVALUATION_THRESHOLD = float(os.getenv('EVALUATION_THRESHOLD', '60'))  # Default to 60 if not set

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_evaluation(finding) -> float:
    """
    Get evaluation score for a finding
    Returns:
        float: evaluation score (0-100), or -1 if API error
    """
    try:
        # Reload environment variables
        load_dotenv(override=True)
        
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.error("Environment variable ANTHROPIC_API_KEY is not set")
            return 80  # Default to accepting findings if API key is not set
        
        client = Anthropic(api_key=api_key)  # Explicitly pass API key
        logger.info("Making API call to Claude...")
        
        # Handle code_references format
        code_refs = finding.code_references
        if isinstance(code_refs, str):
            import json
            code_refs = json.loads(code_refs)
        code_locations = ', '.join(code_refs) if code_refs else 'No code references'
        
        prompt = f"""You are a security expert who evaluates vulnerability findings. Give high scores (>80) to findings with clear descriptions, appropriate severity levels, and actionable recommendations.

        Rate this finding from 0-100 based on:
        1. Clarity and specificity of title and description
        2. Appropriateness of severity rating
        3. Actionability of recommendation
        4. Precision of code references
        5. Quality of exploit PoC if provided
        
        Finding to evaluate:
        Title: {finding.title}
        Description: {finding.description}
        Severity: {finding.severity}
        Code Locations: {code_locations}
        Recommendation: {finding.recommendation}
        Exploit PoC: {finding.exploit_poc or 'Not provided'}
        
        Reply only with a number 0-100."""
        
        try:
            response = client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=10,
                temperature=0,
                system="You are a security expert who evaluates vulnerability findings. Give high scores (>80) to findings with clear descriptions, appropriate severity levels, and actionable recommendations.",
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            if not response.content:
                logger.error("No content in Claude response")
                return 0
                
            try:
                score = float(response.content[0].text.strip())
                score = max(0, min(100, score))
                logger.info(f"Validity score for {finding.finding_id}: {score}")
                return score
            except ValueError:
                logger.error("Failed to parse score from Claude response")
                return 0
                
        except Exception as e:
            if "insufficient_quota" in str(e) or "429" in str(e):
                logger.warning("API quota exceeded, skipping evaluation")
                return -1
            logger.error(f"Error using Claude API: {str(e)}")
            return 0
            
    except Exception as e:
        logger.error(f"Error in evaluation: {str(e)}")
        return 0

def evaluate_findings(project_id: str, current_batch_ids: List[int] = None):
    """
    Evaluate findings for a project.
    Marks findings as disputed if their evaluation score is below EVALUATION_THRESHOLD.
    
    Args:
        project_id: Project identifier
        current_batch_ids: List of IDs from the current batch to evaluate. If None, evaluate all findings.
    """
    logger.info(f"Starting evaluation for project {project_id}")
    project_table = get_project_table(project_id)
    total_evaluated = 0
    disputed_count = 0
    
    try:
        with get_db_connection() as connection:
            # Get findings that need evaluation - only unique findings
            if current_batch_ids:
                select_stmt = select(project_table).where(
                    project_table.c.id.in_(current_batch_ids),
                    project_table.c.status == 'unique'  # Only evaluate unique findings
                )
            else:
                select_stmt = select(project_table).where(
                    project_table.c.status == 'unique'  # Only evaluate unique findings
                )
                
            findings = connection.execute(select_stmt).fetchall()
            
            if not findings:
                logger.info("No findings to evaluate")
                return 0, 0
                
            for finding in findings:
                try:
                    score = get_evaluation(finding)
                    if score < 0:  # API error
                        logger.warning("API quota exceeded or error, accepting finding")
                        continue
                        
                    if score < EVALUATION_THRESHOLD:
                        logger.info(f"Finding {finding.finding_id} marked as disputed (score: {score})")
                        update_stmt = update(project_table).where(
                            project_table.c.id == finding.id
                        ).values(
                            status='disputed',
                            details=f"Validity score: {score}"
                        )
                        connection.execute(update_stmt)
                        disputed_count += 1
                    
                    total_evaluated += 1
                    
                except Exception as e:
                    logger.error(f"Error evaluating finding {finding.finding_id}: {str(e)}")
                    continue
                    
            connection.commit()
            
    except Exception as e:
        logger.error(f"Error in evaluation process: {str(e)}")
        raise
        
    return total_evaluated, disputed_count

def update_finding_status(connection, project_table, finding_id: int, status: str, reason: str) -> None:
    """Update the status of a finding in the database."""
    update_stmt = (
        update(project_table)
        .where(project_table.c.id == finding_id)
        .values(status=status)
    )
    connection.execute(update_stmt)
    logger.info(f"Finding {finding_id} marked as {status}: {reason}") 