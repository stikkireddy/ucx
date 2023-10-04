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


@credentials_provider('github-azure-oidc', ['host', 'azure_client_id'])
def github_azure_oidc(cfg: 'Config') -> Optional[HeaderFactory]:
    # Client ID is the minimal thing we need, as otherwise we get
    # AADSTS700016: Application with identifier 'https://token.actions.githubusercontent.com' was not found
    # in the directory '...'.
    if not cfg.is_azure:
        return None
    if 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' not in os.environ:
        # not in GitHub actions
        return None

    # See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers
    headers = {'Authorization': f"Bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}" }
    endpoint = f"{os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']}&audience=api://AzureADTokenExchange"
    response = requests.get(endpoint, headers=headers)

    # get the ID Token with aud=api://AzureADTokenExchange sub=repo:org/repo:environment:name
    client_assertion = response.json()['value']

    logger.info("Configured AAD token for GitHub Actions OIDC (%s)", cfg.azure_client_id)
    params = {"resource": cfg.effective_azure_login_app_id,
               'client_assertion': client_assertion,
               'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'}
    aad_endpoint = cfg.arm_environment.active_directory_endpoint
    if not cfg.azure_tenant_id:
        # detect Azure AD Tenant ID
        cfg.azure_tenant_id = cfg.oidc_endpoints.token_endpoint.replace(aad_endpoint, '').split('/')[0]
    inner = ClientCredentials(client_id=cfg.azure_client_id,
                              client_secret=cfg.azure_client_secret,
                              token_url=f"{aad_endpoint}{cfg.azure_tenant_id}/oauth2/token",
                              endpoint_params=params,
                              use_params=True)

    def refreshed_headers() -> Dict[str, str]:
        return {'Authorization': f"Bearer {inner.token().access_token}", }

    return refreshed_headers


if __name__ == '__main__':
    w = WorkspaceClient(credentials_provider=github_azure_oidc)
    print(f'ME: {w.current_user.me()}')