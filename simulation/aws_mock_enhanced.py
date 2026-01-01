"""Enhanced mock AWS SDK with more operations."""
from typing import Dict, Any
from datetime import datetime
import json

from .aws_mock import MockAWSClients

class MockAWSClientsEnhanced(MockAWSClients):
    """Enhanced mock AWS clients with more operations."""
    
    def get_iam_client(self):
        """Mock IAM client with more operations."""
        class MockIAMClientEnhanced:
            def __init__(self, parent):
                self.parent = parent
            
            def detach_role_policy(self, **kwargs):
                return self.parent.log_intent("iam", "DetachRolePolicy", kwargs)
            
            def detach_user_policy(self, **kwargs):
                return self.parent.log_intent("iam", "DetachUserPolicy", kwargs)
            
            def attach_role_policy(self, **kwargs):
                return self.parent.log_intent("iam", "AttachRolePolicy", kwargs)
            
            def attach_user_policy(self, **kwargs):
                return self.parent.log_intent("iam", "AttachUserPolicy", kwargs)
            
            def update_access_key(self, **kwargs):
                return self.parent.log_intent("iam", "UpdateAccessKey", kwargs)
            
            def get_role(self, **kwargs):
                return {
                    "Role": {
                        "RoleName": kwargs.get("RoleName", "test-role"),
                        "Arn": f"arn:aws:iam::123456789012:role/{kwargs.get('RoleName', 'test-role')}",
                        "AssumeRolePolicyDocument": {}
                    }
                }
            
            def get_user(self, **kwargs):
                return {
                    "User": {
                        "UserName": kwargs.get("UserName", "test-user"),
                        "Arn": f"arn:aws:iam::123456789012:user/{kwargs.get('UserName', 'test-user')}"
                    }
                }
            
            def list_attached_role_policies(self, **kwargs):
                return {
                    "AttachedPolicies": [
                        {
                            "PolicyName": "AdministratorAccess",
                            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
                        }
                    ]
                }
        
        return MockIAMClientEnhanced(self)
    
    def get_s3_client(self):
        """Mock S3 client with more operations."""
        class MockS3ClientEnhanced:
            def __init__(self, parent):
                self.parent = parent
            
            def put_public_access_block(self, **kwargs):
                return self.parent.log_intent("s3", "PutPublicAccessBlock", kwargs)
            
            def put_bucket_encryption(self, **kwargs):
                return self.parent.log_intent("s3", "PutBucketEncryption", kwargs)
            
            def put_bucket_policy(self, **kwargs):
                return self.parent.log_intent("s3", "PutBucketPolicy", kwargs)
            
            def get_public_access_block(self, **kwargs):
                # Return mock configuration
                return {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False
                    }
                }
            
            def get_bucket_policy_status(self, **kwargs):
                return {
                    "PolicyStatus": {
                        "IsPublic": True  # Simulate a public bucket
                    }
                }
        
        return MockS3ClientEnhanced(self)
    
    def get_ec2_client(self):
        """Mock EC2 client."""
        class MockEC2Client:
            def __init__(self, parent):
                self.parent = parent
            
            def revoke_security_group_ingress(self, **kwargs):
                return self.parent.log_intent("ec2", "RevokeSecurityGroupIngress", kwargs)
            
            def authorize_security_group_ingress(self, **kwargs):
                return self.parent.log_intent("ec2", "AuthorizeSecurityGroupIngress", kwargs)
            
            def describe_security_groups(self, **kwargs):
                # Return mock security group data
                return {
                    "SecurityGroups": [
                        {
                            "GroupId": kwargs.get("GroupIds", ["sg-12345678"])[0],
                            "GroupName": "test-sg",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                                }
                            ]
                        }
                    ]
                }
        
        return MockEC2Client(self)