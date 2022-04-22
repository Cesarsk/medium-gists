import json
import os
import sys
import jwt_verifier
import re

WORKSPACE = os.environ['WORKSPACE']
REGION = 'eu-central-1'
FILENAME = 'pools_map.json'


def verify_user_pool_id(pools_map, workspace, user_pool_id):
    return pools_map[workspace]['pool_id'] == user_pool_id


def extract_groups(app_client, pools_map):
    # given an app_client, returns its group based on the mapping pools_map
    for i in pools_map[WORKSPACE]['app_clients']:
        if app_client == i['id']:
            return i['groups']


def build_context(item, pools_map):
    # in my case I do some processing to extract from the jwt some attributes,
    # feel free to ignore and customize your function to your need
    app_client = item['aud'] if 'aud' in item else item['client_id']
    x_auth_groups = item['cognito:groups'] if 'cognito:groups' in item else extract_groups(app_client, pools_map)
    x_auth_family = [re.sub("([A-Z])", " \\1", i.split('#')[1]).strip() for i in x_auth_groups if 'family#' in i]
    return {
        'X_AUTH_USER_ID': json.dumps(item['cognito:username'] if 'cognito:username' in item else item['client_id']),
        'X_AUTH_GROUPS': json.dumps(x_auth_groups),
        'X_AUTH_FAMILY': json.dumps(x_auth_family),
    }


def handler(message, context):
    try:
        return main(message, context)
    except Exception as e:
        error_type, error_message, _ = sys.exc_info()
        raise e


def authorize_user(principal_id, effect, resource, context):
    # this is the inline policy returned by the lambda.
    response = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        },
    }

    # attach a context with the extra attributes that will be passed downstream to the next service
    # in my case, AppSync
    if context:
        response['context'] = context

    return response


def load_json_config(filename):
    with open(filename) as config_file:
        json_config = json.load(config_file)

    return json_config


def main(message, context):
    token = message['authorizationToken']
    resource = message['methodArn']

    # load json map files
    """
    {
      "qual": {
        "pool_id": "eu-central-1_id",
        "app_clients": [
          {
            "name": "API-qual-sample",
            "id": "abc1234",
            "groups": [
            "Some info here",
            "Some info there"
            ]
          }
        ]
      },
    """
    pools_map = load_json_config(FILENAME)

    # get unverified claims from token and some of its attrs
    unverified_claims = jwt_verifier.get_unverified_claims(token)
    iss = unverified_claims['iss'].split('/')[-1]
    token_use_type = unverified_claims['token_use']

    # check if token is of type cognito app client or cognito user
    if token_use_type == 'access':
        app_client_id = unverified_claims['client_id']
    elif token_use_type == 'id':
        app_client_id = unverified_claims['aud']
    else:
        raise Exception("not handled token_use_type: " + token_use_type)

    # verify if token has a valid user pool id
    check_user_pool_id = verify_user_pool_id(pools_map, WORKSPACE, iss)

    if check_user_pool_id:
        # download jwks
        keys_url = f'https://cognito-idp.{REGION}.amazonaws.com/{iss}/.well-known/jwks.json'
        keys = jwt_verifier.download_jwks(keys_url=keys_url)

        # verify the unverified claims
        verified_claims = jwt_verifier.verify_jwt(token=token,
                                                  keys=keys,
                                                  app_client_id=app_client_id,
                                                  verify_expiration=False)
    else:
        raise Exception(f"Verification failed. Status: check_user_pool_id: {check_user_pool_id}")

    if verified_claims:
        # context will be added as headers in api gateway
        context = build_context(verified_claims, pools_map)

        return authorize_user(principal_id=context['X_AUTH_USER_ID'],
                              effect='Allow',
                              resource=resource,
                              context=context)

    else:
        return authorize_user(principal_id='Unauthorized',
                              effect='Deny',
                              resource=resource,
                              context=None)


# to test the workflow from your local environment
if __name__ == '__main__':
    try:
        token = ''

        message = {
            'type': 'TOKEN',
            'methodArn': 'arn:aws:execute-api:eu-central-1:account_id:api_id/stage/GET/',
            'authorizationToken': token
        }

        response = main(message, None)
        print(response)
    except Exception as e:
        raise e
