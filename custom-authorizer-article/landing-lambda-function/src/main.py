import json


def handler(event, context):
    print(event)

    try:
        x_auth_user_id = event['request']['headers']['x_auth_user_id']
    except KeyError:
        x_auth_user_id = "appsync"

    try:
        x_auth_family = event['request']['headers']['x_auth_family']
        x_auth_family = json.loads(x_auth_family)
    except KeyError:
        x_auth_family = []

    print(x_auth_user_id)
    print(x_auth_family)
