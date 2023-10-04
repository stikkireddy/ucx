import base64
import json
import logging
import os
from typing import Optional, Dict

import requests
from databricks.sdk import WorkspaceClient
from databricks.sdk.core import credentials_provider, Config, HeaderFactory
from databricks.sdk.oauth import TokenSource, ClientCredentials

logger = logging.getLogger(__name__)


@credentials_provider('github-azure-oidc', ['host'])
def github_azure_oidc(cfg: 'Config') -> Optional[HeaderFactory]:
    if not cfg.is_azure:
        return None
    if 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' not in os.environ:
        print(f'NOPE?...')
        # not in GitHub actions
        return None

    # Environment variables are public:
    # https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers#adding-permissions-settings
    headers = {'Authorization': f"Bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}" }
    endpoint = f"{os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']}&audience=api://AzureADTokenExchange"
    response = requests.get(endpoint, headers=headers)

    client_assertion = response.json()['value']

    _, payload, _ = client_assertion.split(".")
    b64_decoded = base64.standard_b64decode(payload + "==").decode("utf8")
    # claims are: 'jti', 'sub', 'aud', 'ref', 'sha', 'repository', 'repository_owner', 'repository_owner_id', 'run_id',
    # 'run_number', 'run_attempt', 'repository_visibility', 'repository_id', 'actor_id', 'actor', 'workflow',
    # 'head_ref', 'base_ref', 'event_name', 'ref_protected', 'ref_type', 'workflow_ref', 'workflow_sha', 'environment',
    # 'environment_node_id', 'job_workflow_ref', 'job_workflow_sha', 'runner_environment', 'enterprise', 'iss', 'nbf',
    # 'exp', 'iat'
    claims = json.loads(b64_decoded)

    print(f'aud={claims["aud"]} sub={claims["sub"]}')

    def token_source_for(resource: str) -> TokenSource:
        aad_endpoint = cfg.arm_environment.active_directory_endpoint
        return ClientCredentials(client_id=cfg.azure_client_id,
                                 client_secret=cfg.azure_client_secret,
                                 token_url=f"{aad_endpoint}{cfg.azure_tenant_id}/oauth2/token",
                                 endpoint_params={"resource": resource,
                                                  'client_assertion': client_assertion,
                                                  'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'},
                                 use_params=True)

    logger.info("Configured AAD token for Service Principal (%s)", cfg.azure_client_id)
    inner = token_source_for(cfg.effective_azure_login_app_id)

    def refreshed_headers() -> Dict[str, str]:
        return {'Authorization': f"Bearer {inner.token().access_token}", }

    return refreshed_headers


if __name__ == '__main__':
    w = WorkspaceClient(credentials_provider=github_azure_oidc)
    print(f'ME: {w.current_user.me()}')