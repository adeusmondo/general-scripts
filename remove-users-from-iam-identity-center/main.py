# TODO: Transformar em um CLI

import boto3

import logging

logger = logging.getLogger()
logger.setLevel('INFO')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s] | %(message)s'))
logger.addHandler(handler)

# Preencha essas constantes para que o script seja executado
PROFILE = ''
IDENTITY_STORE_ID = ''
USERS_TO_BE_REMOVED = []


def filter_input_users_from_identity_store(identity_store_users, input_users):
    logger.info('Iniciando filtro dos usuários...')

    filtered_users = [isu for isu in identity_store_users if isu["name"] in input_users]
    logger.debug(f'Usuários do input encontrados no Identity Store: {filtered_dicts}')

    users_not_founded_in_identity_store = [user for user in input_users if all(user not in isu.values() for isu in identity_store_users)]
    logger.info(f'Usuários que não serão removidos do Identity Store pois não foram encontrados: {users_not_founded_in_identity_store}')
    logger.debug(f'Usuários encontrados: {len(filtered_dicts)} --- Usuários não encotrados: {len(usernames_without_corresponding_key)}')
    
    return filtered_users


class AWSClient():
    def __init__(self, profile: str, region: str = 'us-east-1'):
        self.__session = boto3.Session(profile_name=profile)
        self.__region = region

    def list_users_in_identity_store(self, identity_store_id: str):
        logger.info('Iniciando processo de listagem de usuários no Identity Store.')
        try:
            client = self.__session.client('identitystore', region_name=self.__region)
            users_info = {'users_list': [], 'next_token': None}
            run = True  
            while run:
                if users_info['next_token']:
                    users = client.list_users(
                        IdentityStoreId=identity_store_id,
                        NextToken=users_info['next_token']
                    )
                else:
                    users = client.list_users(
                        IdentityStoreId=identity_store_id
                    )

                users_info['users_list'].extend(users['Users'])

                if users.get('nextToken'):
                    users_info['next_token'] = users['NextToken']
                    logger.info('Buscando mais usuários...')
                else:
                    run = False
                    logger.info('Processo de busca de usuários finalizado.')

            logger.info(f'Qtd de usuários encontrados: {len(users_info["users_list"])}')

            users = []
            for user in users_info['users_list']:
                users.append({'name': user['UserName'], 'id': user['UserId']})

            logger.debug(f'ID dos usuarios: {users}')
            
            return users
        except Exception as exc:
            logger.exception(f'Algo de errado ocorreu durante a execução: {exc}')
            raise exc

    def delete_user_from_identity_store(self, identity_store_id, user_id):
        try:
            client = self.__session.client('identitystore', region_name=self.__region)
            _ = client.delete_user(
                IdentityStoreId=identity_store_id, 
                UserId=user_id
            )
            logger.info('Usuário deletado do Identity Store...')
        except Exception as exc:
            logger.exception(f'Algo de errado ocorreu durante a execução: {exc}')
            raise exc

    
if __name__ == '__main__':
    logger.info(f'Iniciando execução do script de remoção de usuários do Identity Store ({IDENTITY_STORE_ID})...')
    if PROFILE == '' or IDENTITY_STORE_ID == '' or USERS_TO_BE_REMOVED == []:
        logger.error('O script não será executado pois as constantes necessarias para sua execução não foram preenchidas...')
        exit(1)

    try:
        aws_client = AWSClient(profile=PROFILE)
        identity_store_users = aws_client.list_users_in_identity_store(
            identity_store_id=IDENTITY_STORE_ID
        )
        filtered_users = filter_input_users_from_identity_store(
            identity_store_users,
            USERS_TO_BE_REMOVED
        )
        for user in filtered_users:
            logger.info(f'Iniciando processo de remoção do usuario {user["name"]} no Identity Store')
            _ = aws_client.delete_user_from_identity_store(
                identity_store_id=IDENTITY_STORE_ID,
                user_id=user['id']
            )
    except Exception as exc:
        logger.exception(f'Algo de errado ocorreu durante a execução: {exc}')
        exit(1)
