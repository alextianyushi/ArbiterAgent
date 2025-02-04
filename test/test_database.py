import json
import os
import sys

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import insert_findings

def test_database():
    """Test database operations using JSON test data"""
    # Load test data from JSON file
    with open(os.path.join(os.path.dirname(__file__), 'test_data.json'), 'r') as f:
        test_data = json.load(f)
    
    # Process each project
    for project in test_data['projects']:
        try:
            print(f"\nProcessing project: {project['project_id']}")
            print("-" * 50)
            
            # Insert findings for this project
            insert_findings(
                project_id=project['project_id'],
                agent_id=project['agent_id'],
                findings=project['findings'],
                metadata=project.get('metadata')
            )
            print(f"Successfully inserted findings for project: {project['project_id']}")
            
        except Exception as e:
            print(f"Error processing project {project['project_id']}: {str(e)}")
    
    print("\nData inserted successfully. You can now view it using DB Browser for SQLite.")

if __name__ == "__main__":
    test_database() 