import fnmatch
import json
import os

import jwt
import requests
from jwt import InvalidAudienceError
from jwt.algorithms import RSAAlgorithm

from . import KeyProvider

JWKS_URL = "https://gitlab.miquido.com/oauth/discovery/keys"
OIDC_JSON = os.getenv('OIDC')

oidc = [{"application_id": "b16cd300-bdc8-48c8-b091-8bda0eae80ce", "aud": "scaleway-gitlab-test", "session_length": 10,
         "sub": "project_path:miquido/devops/scaleway/backend:ref_type:branch:ref:*"}]


class ScwGitlabOidc:
    def __init__(self, key_provider: KeyProvider):
        self.key_provider = key_provider

    def verify_token(self, token, jwk_public_part):
        print(f"token = {token}")
        pair = self.key_provider.get_key_pair()
        print(pair)

        jwks = requests.get(JWKS_URL).json()

        print(f"jwks = {jwks}")

        # Extract the public key from the JWKS
        def get_public_key(jwks, kid):
            for key in jwks['keys']:
                if key['kid'] == kid:
                    return RSAAlgorithm.from_jwk(json.dumps(jwk_public_part))
            raise ValueError("Key ID not found in JWKS")

        # Get the Key ID (kid) from the token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header['kid']

        print(f"unverified_header {unverified_header}")
        print(f"kid {kid}")

        # Get the public key
        public_key = get_public_key(jwks, kid)

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
                        keys = "tbd" #create_api_key("test", conf['application_id'], claims["sub"], conf['session_length'])

                        return {
                            "body": keys,
                            "statusCode": 200,
                        }
            except InvalidAudienceError as e:
                continue
        print(f"returning LOG. Nothing found")
