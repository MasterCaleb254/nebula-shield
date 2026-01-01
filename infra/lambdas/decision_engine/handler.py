"""Decision Engine Lambda handler for CDK deployment."""
import json
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Decision Engine Lambda handler."""
    logger.info(f"Received event: {json.dumps(event, default=str)}")
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Decision Engine processing completed",
            "event": event
        })
    }
