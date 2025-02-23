from sqlalchemy import select, update
from typing import Dict, List, Set, Tuple
import os
import json
from app.database import get_project_table, get_db_connection, DatabaseError
from anthropic import Anthropic
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Get configuration from environment variables
OVERLAP_THRESHOLD = float(os.getenv('OVERLAP_THRESHOLD', '0.2'))  # Default to 0.2 if not set
SIMILARITY_THRESHOLD = float(os.getenv('SIMILARITY_THRESHOLD', '80'))  # Default to 80 if not set

def get_code_references_overlap(refs1: List[str], refs2: List[str]) -> float:
    """
    Calculate the overlap ratio between two lists of code references.
    
    Args:
        refs1: First list of code references
        refs2: Second list of code references
        
    Returns:
        float: Overlap ratio between 0 and 1
    """
    # Convert string to list if needed (for SQLite storage)
    if isinstance(refs1, str):
        refs1 = json.loads(refs1)
    if isinstance(refs2, str):
        refs2 = json.loads(refs2)
    
    # Handle empty lists
    if not refs1 or not refs2:
        return 0.0
        
    # Convert to sets for intersection
    set1 = set(refs1)
    set2 = set(refs2)
    
    # Calculate Jaccard similarity: intersection / union
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    return intersection / union if union > 0 else 0.0

def get_similarity_score(finding1, finding2) -> float:
    """
    Compare two findings and return a similarity score between 0 and 100.
    Uses Claude API to analyze semantic similarity of findings.
    
    Args:
        finding1: First finding record
        finding2: Second finding record
        
    Returns:
        float: Similarity score between 0 and 100
        
    Raises:
        ValueError: If API key is not set
        Exception: If API call fails
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY not set")
        raise ValueError("ANTHROPIC_API_KEY not set")
    
    client = Anthropic(api_key=api_key)
    
    # Calculate code references overlap
    code_overlap = get_code_references_overlap(
        finding1.code_references or [],
        finding2.code_references or []
    )
    
    prompt = f"""Compare these two security findings and rate their similarity from 0-100:
    
    Finding 1:
    Title: {finding1.title}
    Description: {finding1.description}
    Exploit: {finding1.exploit_poc or 'N/A'}
    
    Finding 2:
    Title: {finding2.title}
    Description: {finding2.description}
    Exploit: {finding2.exploit_poc or 'N/A'}
    
    Consider:
    1. Title and description semantic similarity
    2. Exploit code similarity (if available)
    3. Code overlap ratio: {code_overlap}
    4. Severity levels: {finding1.severity} vs {finding2.severity}
    
    Reply only with a number 0-100."""
    
    response = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=10,
        temperature=0,
        messages=[{"role": "user", "content": prompt}]
    )
    
    if not response.content:
        logger.error("Empty response from Claude API")
        raise Exception("Empty response from Claude API")
        
    try:
        return float(response.content[0].text.strip())
    except (ValueError, IndexError) as e:
        logger.error(f"Failed to parse similarity score: {str(e)}")
        raise Exception(f"Failed to parse similarity score: {str(e)}")

def check_duplicates(project_id: str, current_batch_ids: List[int] = None) -> Tuple[int, int]:
    """
    Process findings and mark duplicates using AI-based similarity detection.
    Compares each finding with:
    1. Other findings in the same batch
    2. Existing unique findings in the database
    
    Uses code reference overlap as pre-filter before AI similarity check.
    Thresholds:
    - OVERLAP_THRESHOLD: Minimum code overlap ratio to trigger AI check (from env)
    - SIMILARITY_THRESHOLD: Minimum AI similarity score to mark as duplicate (from env)
    
    Args:
        project_id: Project identifier
        current_batch_ids: List of IDs from current batch to check. If None, check all findings.
        
    Returns:
        Tuple[int, int]: Count of (processed findings, duplicates found)
        
    Raises:
        DatabaseError: If database operations fail
        Exception: If similarity check fails
    """
    logger.info(f"Starting duplicate check for project {project_id}")
    project_table = get_project_table(project_id)
    total_processed = duplicate_count = 0
    
    try:
        with get_db_connection() as connection:
            # Get findings to process
            if current_batch_ids:
                pending_findings = connection.execute(
                    select(project_table).where(
                        project_table.c.id.in_(current_batch_ids),
                        project_table.c.status == 'pending'
                    )
                ).fetchall()
            else:
                pending_findings = connection.execute(
                    select(project_table).where(
                        project_table.c.status == 'pending'
                    )
                ).fetchall()
            
            if not pending_findings:
                logger.info("No findings to process")
                return 0, 0
            
            # Get existing unique findings
            existing_findings = connection.execute(
                select(project_table).where(
                    project_table.c.status == 'unique'
                )
            ).fetchall()
            
            # Process each finding
            for i, finding in enumerate(pending_findings):
                try:
                    highest_similarity = 0
                    similar_finding = None
                    
                    # Compare with existing unique findings
                    for existing in existing_findings:
                        # Pre-filter using code overlap
                        overlap = get_code_references_overlap(
                            finding.code_references or [],
                            existing.code_references or []
                        )
                        # Only proceed with AI similarity check if there's significant code overlap
                        if overlap > OVERLAP_THRESHOLD:
                            similarity = get_similarity_score(finding, existing)
                            if similarity > highest_similarity:
                                highest_similarity = similarity
                                similar_finding = existing
                    
                    # Compare with other findings in current batch
                    for other_finding in pending_findings[i+1:]:
                        if other_finding.status == 'duplicated':
                            continue
                            
                        overlap = get_code_references_overlap(
                            finding.code_references or [],
                            other_finding.code_references or []
                        )
                        if overlap > OVERLAP_THRESHOLD:
                            similarity = get_similarity_score(finding, other_finding)
                            if similarity > highest_similarity:
                                highest_similarity = similarity
                                similar_finding = other_finding
                    
                    # Mark as duplicate if similarity exceeds threshold
                    if highest_similarity >= SIMILARITY_THRESHOLD:
                        duplicate_count += 1
                        connection.execute(
                            update(project_table)
                            .where(project_table.c.id == finding.id)
                            .values(
                                status='duplicated',
                                details=f"Similar to finding {similar_finding.finding_id} (similarity: {highest_similarity}%)"
                            )
                        )
                    else:
                        connection.execute(
                            update(project_table)
                            .where(project_table.c.id == finding.id)
                            .values(status='unique')
                        )
                    
                    total_processed += 1
                    
                except Exception as e:
                    logger.error(f"Error processing finding {finding.finding_id}: {str(e)}")
                    raise
                
            connection.commit()
            logger.info(f"Processed {total_processed} findings, found {duplicate_count} duplicates")
            return total_processed, duplicate_count
            
    except Exception as e:
        logger.error(f"Error in duplicate check: {str(e)}")
        raise