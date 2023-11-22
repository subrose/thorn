""" Client with helpers for similating vault usecases """

from typing import Any, Optional, List
import requests

from pydantic import BaseModel


class Policy(BaseModel):
    policy_id: str
    effect: str
    actions: List[str]
    resources: List[str]


def check_expected_status(
    response: requests.Response, expected_status_codes: Optional[list[int]]
):
    if expected_status_codes is None:
        return
    if response.status_code not in expected_status_codes:
        raise Exception(
            f"""Request failed
            path={response.request.path_url}, body={response.request.body}
            headers={response.request.headers}
            {response.status_code} not in {expected_status_codes=} 
            {response.reason}, {response.text}
            """
        )


class Actor:
    def __init__(self, vault_url: str, username: str, password: str):
        self.username = username
        self.password = password
        self.vault_url = vault_url

    def create_principal(
        self,
        username: str,
        password: str,
        description: str,
        policies: List[str],
        expected_statuses: Optional[list[int]] = None,
    ) -> dict[str, str]:
        response = requests.post(
            f"{self.vault_url}/principals",
            json={
                "username": username,
                "password": password,
                "description": description,
                "policies": policies,
            },
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def delete_principal(
        self,
        username: str,
        expected_statuses: Optional[list[int]] = None,
    ) -> None:
        response = requests.delete(
            f"{self.vault_url}/principals/{username}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return

    def create_collection(
        self, schema: dict[str, Any], expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.post(
            f"{self.vault_url}/collections",
            json=schema,
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)

    def create_records(
        self,
        collection: str,
        records: List[dict[str, str]],
        expected_statuses: Optional[list[int]] = None,
    ) -> list[str]:
        response = requests.post(
            f"{self.vault_url}/collections/{collection}/records",
            json=records,
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def get_record(
        self,
        collection: str,
        record_id: str,
        return_formats: str,
        expected_statuses: Optional[list[int]] = None,
    ) -> dict[str, dict[str, str]]:
        response = requests.get(
            f"{self.vault_url}/collections/{collection}/records/{record_id}",
            params={"formats": return_formats},
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def create_policy(
        self, policy: Policy, expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.post(
            f"{self.vault_url}/policies",
            auth=(self.username, self.password),
            json=policy.model_dump(),
        )
        check_expected_status(response, expected_statuses)

    def get_policy(
        self, policy_id: str, expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.get(
            f"{self.vault_url}/policies/{policy_id}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def delete_policy(
        self, policy_id: str, expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.delete(
            f"{self.vault_url}/policies/{policy_id}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return
