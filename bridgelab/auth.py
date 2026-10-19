"""OAuth authentication for the BridgeLab agent identity."""

import httpx


class AgentAuth:
    """Authenticate to Keycloak using client_credentials grant."""

    def __init__(self, keycloak_url: str, client_id: str, client_secret: str, realm: str = "bridgelab"):
        self.keycloak_url = keycloak_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.realm = realm
        self._token: str | None = None

    def get_token(self) -> str:
        if self._token:
            return self._token
        url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        resp = httpx.post(url, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        })
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token


class MockAuth:
    """Mock auth that returns a synthetic token without network calls."""

    def __init__(self, client_id: str = "bridgelab-agent"):
        self.client_id = client_id

    def get_token(self) -> str:
        return f"mock-token-{self.client_id}-bridgelab"


class EntraAgentAuth:
    """Authenticate to Microsoft Entra ID using client_credentials grant (MSAL).

    Requires the optional `entra` dependency group (`pip install .[entra]`);
    msal is imported lazily so the base install stays Entra-free unless this
    class is actually used.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str = "https://graph.microsoft.com/.default",
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self._token: str | None = None

    def get_token(self) -> str:
        if self._token:
            return self._token
        import msal

        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )
        result = app.acquire_token_for_client(scopes=[self.scope])
        if "access_token" not in result:
            raise RuntimeError(
                "Entra token acquisition failed: "
                f"{result.get('error')}: {result.get('error_description')}"
            )
        self._token = result["access_token"]
        return self._token
