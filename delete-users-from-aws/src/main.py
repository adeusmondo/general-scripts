import boto3
import typer

import logging
import re
import socket
import sys
import time
import urllib3
import webbrowser

from typing import List, Optional

logger = logging.getLogger()
logger.setLevel('INFO')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s] | %(message)s'))
logger.addHandler(handler)

SSO_URL = "https://gruponc.awsapps.com/start"

class AWSClient:
    def __init__(self, profile: str, region: str):
        boto3.setup_default_session(profile_name=profile)
        self.client = boto3.client('iam', aws_session_token=None)
        self.iam_users = self.get_users(max_items=1000)

    def get_users(self, max_items: Optional[int] = 100):
        try:
            response = self.client.list_users( MaxItems=max_items)
            if response is None:
                logger.error('Something happen with the list users call. No response return')
                exit(1)
            
            if response.get('Users') == []:
                logger.info('None users returned')
                exit(1)

            return response.get('Users')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def list_access_keys(self, user_name: str, max_items: Optional[int] = 100):
        try:
            response = self.client.list_access_keys( 
                UserName=user_name,
                MaxItems=max_items
            )
            if response is None:
                logger.error('Something happen with the list access keys call. No response return')
                return []
            
            if response.get('AccessKeyMetadata') == []:
                logger.info('None access keys returned')
                return []

            return response.get('AccessKeyMetadata')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def list_attached_user_policies(self, user_name: str, max_items: Optional[int] = 100):
        try:
            response = self.client.list_attached_user_policies( 
                UserName=user_name,
                MaxItems=max_items
            )
            if response is None:
                logger.error('Something happen with the list attached user policies call. No response return')
                return []
            
            if response.get('AttachedPolicies') == []:
                logger.info('None attached policies returned')
                return []

            return response.get('AttachedPolicies')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def list_user_policies(self, user_name: str, max_items: Optional[int] = 100):
        try:
            response = self.client.list_user_policies( 
                UserName=user_name,
                MaxItems=max_items
            )
            if response is None:
                logger.error('Something happen with the list user policies call. No response return')
                return []
            
            if response.get('PolicyNames') == []:
                logger.info('None user policies returned')
                return []

            return response.get('PolicyNames')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def list_groups_for_user(self, user_name: str, max_items: Optional[int] = 100):
        try:
            response = self.client.list_groups_for_user( 
                UserName=user_name,
                MaxItems=max_items
            )
            if response is None:
                logger.error('Something happen with the list groups for user call. No response return')
                return []
            
            if response.get('Groups') == []:
                logger.info('None group returned')
                return []

            return response.get('Groups')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def list_user_mfa_devices(self, user_name: str):
        try:
            response = self.client.list_mfa_devices(
                UserName=user_name
            )
            if response is None:
                logger.error('Something happen with the list mfa devices call. No response return')
                return []
            
            if response.get('MFADevices') == []:
                logger.info('None mfa devices returned')
                return []

            return response.get('MFADevices')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def list_signing_certificates(self, user_name: str, max_items: Optional[int] = 100):
        try:
            response = self.client.list_signing_certificates(
                UserName=user_name
            )
            if response is None:
                logger.error('Something happen with the list signing certificates call. No response return')
                return []
            
            if response.get('Certificates') == []:
                logger.info('None certificates returned')
                return []

            return response.get('Certificates')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def list_ssh_public_keys(self, user_name: str):
        try:
            response = self.client.list_ssh_public_keys(
                UserName=user_name
            )
            if response is None:
                logger.error('Something happen with the list ssh pub keys call. No response return')
                return []
            
            if response.get('SSHPublicKeys') == []:
                logger.info('None ssh pub keys returned')
                return []

            return response.get('SSHPublicKeys')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def list_service_specific_credentials(self, user_name: str):
        try:
            response = self.client.list_service_specific_credentials(
                UserName=user_name
            )
            if response is None:
                logger.error('Something happen with the list service specific credentials call. No response return')
                return []
            
            if response.get('ServiceSpecificCredentials') == []:
                logger.info('None service specific credentials returned')
                return []

            return response.get('ServiceSpecificCredentials')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def delete_access_key(self, user_name: str, access_key_id: str):
        try:
            _ = self.client.delete_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id
            )

            logger.info(f'Access key {access_key_id} from the user {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def delete_user_policy(self, user_name: str, policy_name: str):
        try:
            _ = self.client.delete_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )

            logger.info(f'Police {policy_name} from the user {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def detach_user_policy(self, user_name: str, policy_arn: str):
        try:
            _ = self.client.detach_user_policy(
                UserName=user_name,
                PolicyArn=policy_arn
            )

            logger.info(f'Police {policy_arn} from the user {user_name} on account {self.aws_profile} detach')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def remove_user_from_group(self, user_name: str, group_name: str):
        try:
            _ = self.client.remove_user_from_group(
                UserName=user_name,
                GroupName=group_name
            )

            logger.info(f'User {user_name} removed from group {group_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def deactivate_mfa_device(self, user_name: str, serial_number: str):
        try:
            _ = self.client.deactivate_mfa_device(
                UserName=user_name,
                SerialNumber=serial_number
            )

            logger.info(f'MFA device {serial_number} from the user {user_name} on account {self.aws_profile} deactivate')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def delete_virtual_mfa_device(self, user_name: str, serial_number: str):
        try:
            _ = self.client.delete_virtual_mfa_device(
                SerialNumber=serial_number
            )

            logger.info(f'MFA device {serial_number} from the user {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def delete_signing_certificate(self, user_name: str, certificate_id: str):
        try:
            _ = self.client.delete_signing_certificate(
                UserName=user_name,
                CertificateId=certificate_id
            )

            logger.info(f'Certificate {certificate_id} from the user {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def delete_ssh_public_key(self, user_name: str, ssh_pub_key_id: str):
        try:
            _ = self.client.delete_ssh_public_key(
                UserName=user_name,
                SSHPublicKeyId=ssh_pub_key_id
            )

            logger.info(f'SSH pub key {ssh_pub_key_id} from the user {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def delete_service_specific_credential(self, user_name: str, ssc_id: str):
        try:
            _ = self.client.delete_service_specific_credential(
                UserName=user_name,
                ServiceSpecificCredentialId=ssc_id
            )

            logger.info(f'Service Specific Credential {ssc_id} from the user {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def delete_user(self, user_name: str):
        try:
            _ = self.client.delete_user(
                UserName=user_name
            )

            logger.info(f'User {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')
    
    def delete_login_profile(self, user_name: str):
        try:
            _ = self.client.delete_login_profile(
                UserName=user_name
            )

            logger.info(f'User profile {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')


if __name__ == '__main__':
    users_names = list(sys.argv[1].split(","))
    profiles = list(sys.argv[2].split(","))
    
    for profile in profiles:
        aws_client = AWSClient(profile, 'us-east-1')
        aws_user_names = aws_client.get_users(max_items=1000)

        if aws_user_names is None:
            logger.error('None users returned')
            exit(1)

        aws_user_names = [user['UserName'] for user in aws_user_names]

        for user_name in users_names:
            logger.info(f"Start the proccess to delete {user_name} from {profile}")

            if user_name not in aws_user_names:
                logger.info(f'User {user_name} not existing in this account {profile}')
                continue
            
            ## USER INLINE POLICIES
            user_inline_policies = aws_client.list_user_policies(user_name, max_items=1000)
            logger.info(f'user_inline_policies: {user_inline_policies}')
            if user_inline_policies == []:
                logger.info(f'User {user_name} don\'t have Inline Policies')
            # for user_inline_policy in user_inline_policies:
            #     _ = aws_client.delete_user_policy(user_name, policy_name=user_inline_policy)

            ## USER ATTACHED POLICIES
            user_attached_policies = aws_client.list_attached_user_policies(user_name, max_items=1000)
            logger.info(f'user_attached_policies: {user_attached_policies}')
            if user_attached_policies == []:
                logger.info(f'User {user_name} don\'t have Attached Policies')
            # for user_attached_policy in user_attached_policies:
            #     _ = aws_client.detach_user_policy(user_name, policy_arn=user_attached_policy['PolicyArn'])

            ## GROUPS FOR USER
            groups_for_user = aws_client.list_groups_for_user(user_name, max_items=1000)
            logger.info(f'groups_for_user: {groups_for_user}')
            if groups_for_user == []:
                logger.info(f'User {user_name} don\'t belongs to a group')
            # for group_for_user in groups_for_user:
            #     _ = aws_client.remove_user_from_group(user_name, group_for_user['GroupName'])
                
            ## ACCESS KEYS
            access_keys = aws_client.list_access_keys(user_name, max_items=1000)
            logger.info(f'access_keys: {access_keys}')
            if access_keys == []:
                logger.info(f'User {user_name} don\'t have Access Keys')
            # for access_key in access_keys:
                # _ = aws_client.delete_access_key(user_name, access_key['AccessKeyId'])

            ## CERTIFICATES
            certificates = aws_client.list_signing_certificates(user_name, max_items=1000)
            logger.info(f'certificates: {certificates}')
            if certificates == []:
                logger.info(f'User {user_name} don\'t have Certificates')
            # for certificate in certificates:
                # _ = aws_client.delete_signing_certificate(user_name, certificate['CertificateId'])
            
            ## MFA DEVICES
            mfa_devices = aws_client.list_user_mfa_devices(user_name)
            logger.info(f'mfa_devices: {mfa_devices}')
            if mfa_devices == []:
                logger.info(f'User {user_name} don\'t have MFA device')
            # for mfa_device in mfa_devices:
                # _ = aws_client.deactivate_mfa_device(user_name, serial_number=mfa_device['SerialNumber'])
                # _ = aws_client.delete_virtual_mfa_device(serial_number=mfa_device['SerialNumber'])
                # logger.info(f'MFA Devices from user {user_name} removed')
            
            ## SSH PUB KEYS
            ssh_pub_keys = aws_client.list_ssh_public_keys(user_name)
            logger.info(f'ssh_pub_keys: {ssh_pub_keys}')
            if ssh_pub_keys == []:
                logger.info(f'User {user_name} don\'t have SSH Pub Keys')
            # for ssh_pub_key in ssh_pub_keys:
            #     _ = aws_client.delete_ssh_public_key(user_name, ssh_pub_key['SSHPublicKeyId'])
            
            ## Service Specific Credentials
            service_specific_credentials = aws_client.list_service_specific_credentials(user_name)
            logger.info(f'service_specific_credentials: {service_specific_credentials}')
            if service_specific_credentials == []:
                logger.info(f'User {user_name} don\'t have Service Specific Credentials')
            # for service_specific_credential in service_specific_credentials:
                # _ = aws_client.delete_service_specific_credential(user_name, ssh_pub_key['service_specific_credential'])

            # _ = aws_client.delete_login_profile(user_name)
            # _ = aws_client.delete_user(user_name)
    