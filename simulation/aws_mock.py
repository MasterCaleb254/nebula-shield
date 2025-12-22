"""Mock AWS SDK for local simulation and intent logging."""
from typing import Dict, Any, Optional
from datetime import datetime
import json
from dataclasses import asdict

class MockAWSClients:
    """Mock AWS service clients that log intent instead of making calls"""
    
    def __init__(self, mode: str = "dry_run"):
        self.mode = mode  # "dry_run", "intent_only", "execute" (not used in local)
        self.logs = []
    
    def log_intent(self, service: str, operation: str, params: Dict[str, Any]):
        """Log API call intent"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": service,
            "operation": operation,
            "parameters": params,
            "mode": self.mode,
            "intent": "This API call would be made in production"
        }
        self.logs.append(log_entry)
        print(f"[MOCK AWS] {service}.{operation} called with params: {json.dumps(params, default=str)}")
        
        # Return mock successful response
        return self._mock_response(service, operation)
    
    def _mock_response(self, service: str, operation: str) -> Dict[str, Any]:
        """Generate mock AWS response"""
        response_map = {
            "s3": {
                "PutPublicAccessBlock": {
                    "ResponseMetadata": {"HTTPStatusCode": 200}
                },
                "GetBucketPolicyStatus": {
                    "PolicyStatus": {
                        "IsPublic": False
                    }
                }
            },
            "iam": {
                "DetachRolePolicy": {
                    "ResponseMetadata": {"HTTPStatusCode": 200}
                }
            },
            "ec2": {
                "RevokeSecurityGroupIngress": {
                    "Return": True,
                    "ResponseMetadata": {"HTTPStatusCode": 200}
                }
            }
        }
        
        return response_map.get(service, {}).get(operation, {"ResponseMetadata": {"HTTPStatusCode": 200}})
    
    def get_s3_client(self):
        """Mock S3 client"""
        class MockS3Client:
            def __init__(self, parent):
                self.parent = parent
            
            def put_public_access_block(self, **kwargs):
                return self.parent.log_intent("s3", "PutPublicAccessBlock", kwargs)
            
            def get_bucket_policy_status(self, **kwargs):
                # For simulation, we'll return a mock policy status
                return {
                    "PolicyStatus": {
                        "IsPublic": True  # Simulate a public bucket
                    }
                }
            
            def get_public_access_block(self, **kwargs):
                return {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False
                    }
                }
        
        return MockS3Client(self)
    
    def get_iam_client(self):
        """Mock IAM client"""
        class MockIAMClient:
            def __init__(self, parent):
                self.parent = parent
            
            def detach_role_policy(self, **kwargs):
                return self.parent.log_intent("iam", "DetachRolePolicy", kwargs)
        
        return MockIAMClient(self)
    
    def get_logs(self) -> list:
        """Get all logged intents"""
        return self.logs
    
    def clear_logs(self):
        """Clear intent logs"""
        self.logs = []
