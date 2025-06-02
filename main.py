import os
import fnmatch

import requests
import jwt
from datetime import datetime
from datetime import timedelta
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import InvalidAudienceError
import json

GITLAB_JWKS_URL = os.getenv('GITLAB_JWKS_URL')
GITLAB_AUDIENCE = "scaleway-gitlab"
JWKS_URL = "https://gitlab.miquido.com/oauth/discovery/keys"
SCW_SECRET_KEY = os.getenv('SCW_SECRET_KEY')
OIDC_JSON = os.getenv('OIDC')

oidc = json.loads(OIDC_JSON)


def handle(event, context):
    try:
        print(f'Envs = {list(os.environ.keys())}')

        print("Event:")
        print(event)

        token = event['headers']['Authorization']
        token = token.split(" ")[1]
        print(f"token = {token}")

        jwks = requests.get(JWKS_URL).json()

        print(f"jwks = {jwks}")

        # Extract the public key from the JWKS
        def get_public_key(jwks, kid):
            for key in jwks['keys']:
                if key['kid'] == kid:
                    return RSAAlgorithm.from_jwk(json.dumps(key))
            raise ValueError("Key ID not found in JWKS")

        # Get the Key ID (kid) from the token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header['kid']

        print(f"unverified_header {unverified_header}")
        print(f"kid {kid}")

        # Get the public key
        public_key = get_public_key(jwks, kid)

        print(f"public_key {public_key}")
        print(f"oidc {oidc}")

        auds = {}
        for conf in oidc:
            if conf['aud'] not in auds:
                auds[conf['aud']] = [conf]
            else:
                auds[conf['aud']].append(conf)
        print(f"auds {auds}")
        for key, value in auds.items():
            try:
                claims = jwt.decode(token, public_key, algorithms=["RS256"], audience=key)

                print(f"claims {claims}")

                for conf in value:
                    if fnmatch.fnmatch(claims['sub'], conf['sub']):
                        keys = create_api_key("test", conf['application_id'], claims["sub"], conf['session_length'])

                        return {
                            "body": keys,
                            "statusCode": 200,
                        }
            except InvalidAudienceError as e:
                continue
        print(f"returning LOG. Nothing found")

        return {
            "statusCode": 403,
            "body": {"error": "No sub match found"}
        }

    except Exception as e:
        print(f"exception caughted!")
        print(f"error: {str(e)}")
        return {
            "statusCode": 403,
            "body": {"error": str(e)}
        }


def create_api_key(name, application_id, description, minutes):
    headers = {
        "X-Auth-Token": SCW_SECRET_KEY,
        "Content-Type": "application/json"
    }
    print(f"headers {headers}")
    payload = {
        "name": name,
        "description": description,
        "application_id": application_id,
        "expires_at": (datetime.utcnow() + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    print(f"payload {payload}")

    response = requests.post("https://api.scaleway.com/iam/v1alpha1/api-keys", headers=headers, json=payload)
    print(response.text)
    response.raise_for_status()
    response_data = response.json()

    return {
        'access_key': response_data['access_key'],
        'secret_key': response_data['secret_key'],
    }


if __name__ == '__main__':
    test = handle(
        {
            'headers': {
                'Authorization': 'Bearer xxx'
            },
            'body': {
                'application_id'
            }
        }, {})

    print(test)
