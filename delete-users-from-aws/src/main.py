import boto3
import typer

import logging
import sys

from typing import List, Optional

logger = logging.getLogger()
logger.setLevel('INFO')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s] | %(message)s'))
logger.addHandler(handler)

class AWSClient:
    def __init__(self, profile: str):
        boto3.setup_default_session(profile_name=profile)
        self.aws_profile = profile
        self.client = boto3.client('iam')
        self.iam_users = self.get_users(max_items=1000)

    def get_users(self, max_items: Optional[int] = 100):
        try:
            response = self.client.list_users(MaxItems=max_items)
            if response is None:
                logger.error('Something happen with the list users call. No response return')
            
            if response.get('Users') == []:
                logger.info('None users returned')

            return response.get('Users')
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

    def list_user_mfa_devices(self, user_name: str):
        try:
            response = self.client.list_mfa_devices(
                UserName=user_name
            )
            if response is None:
                logger.error('Something happen with the list mfa devices call. No response return')
                return None
            
            if response.get('MFADevices') == []:
                logger.info('None mfa devices returned')
                return None

            return response.get('MFADevices')
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

    def delete_user(self, user_name: str):
        try:
            _ = self.client.delete_user(
                UserName=user_name
            )

            logger.info(f'User {user_name} on account {self.aws_profile} deleted')
            
        except Exception as exc:
            logger.exception(f'Something wrong happens: {exc}')

if __name__ == '__main__':
    users_names = list(sys.argv[1])
    profiles = list(sys.argv[2])
    
    for profile in profiles:
        aws_client = AWSClient()
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

            response = aws_client.list_user_mfa_devices(user_name)
            if response is None:
                logger.info(f'User {user_name} don\'t have MFA device. Go to delete this user')

                response = aws_client.delete_user(user_name)
                logger.info(f'User {user_name} deleted')

            for mfa_device in response:
                _ = aws_client.deactivate_mfa_device(user_name, serial_number=mfa_device['SerialNumber'])
                _ = aws_client.delete_virtual_mfa_device(serial_number=mfa_device['SerialNumber'])
                # TODO: Delete this itens
                # Password ( DeleteLoginProfile)
                # Access keys ( DeleteAccessKey)
                # Signing certificate ( DeleteSigningCertificate)
                # SSH public key ( DeleteSSHPublicKey)
                # Git credentials ( DeleteServiceSpecificCredential)
                # Inline policies ( DeleteUserPolicy)
                # Attached managed policies ( DetachUserPolicy)
                # Group memberships ( RemoveUserFromGroup)
                _ = aws_client.delete_user(user_name)
    