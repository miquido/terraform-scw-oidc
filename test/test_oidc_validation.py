import base64
import unittest
from scw_gitlab_oidc import ScwGitlabOidc
from scw import ScwKeyProvider
import jwt
from datetime import datetime, timedelta

# Define a test private key (RSA)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class TestScwGitlabOidc(unittest.TestCase):

    def test_show_dialog(self):

        # Define the payload
        payload = {
            "aud": "scaleway-gitlab-test",
            "sub": "test-subject",
            "exp": datetime.utcnow() + timedelta(minutes=5),  # Token expiration time
        }

        # Generate a test private key (RSA)
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Extract the public key from the private key
        public_key_obj = private_key_obj.public_key()

        # Serialize the public key to get the modulus (n) and exponent (e)
        public_numbers = public_key_obj.public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        # Convert the modulus and exponent to base64url format
        n_b64 = base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")).decode("utf-8").rstrip(
            "=")
        e_b64 = base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder="big")).decode("utf-8").rstrip(
            "=")

        # Prepare the JWK public part
        jwk_public_part = {
            "kty": "RSA",
            "kid": "1R2I6ppWSU1F3r34iOkQOn3KsBsyFLT2TfTU5Kq1kjs",
            "e": e_b64,
            "n": n_b64,
            "use": "sig",
            "alg": "RS256"
        }

        private_key = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        # Generate the token
        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "1R2I6ppWSU1F3r34iOkQOn3KsBsyFLT2TfTU5Kq1kjs"})

        print(f"Generated JWT token: {token}")

        ScwGitlabOidc(ScwKeyProvider()).verify_token(token, jwk_public_part)
