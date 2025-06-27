from scw_gitlab_oidc import KeyProvider


class ScwKeyProvider(KeyProvider):
    def get_key_pair(self):
        print("go")
