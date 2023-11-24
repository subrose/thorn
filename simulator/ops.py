from client import Actor, Policy
from wait import wait_for_api
import os

# VAULT_URL from your client.py
VAULT_URL = os.environ.get("VAULT_URL", "http://localhost:3001")
wait_for_api(VAULT_URL)

# Step 0: Initialize your actors

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

SOMEBODY_USERNAME = "somebody"
SOMEBODY_PASSWORD = "somebody-password"

admin = Actor(VAULT_URL, username=ADMIN_USERNAME, password=ADMIN_PASSWORD)

#  Create collection and some records
admin.create_collection(
    schema={
        "name": "secrets",
        "fields": {
            "name": {"type": "string", "indexed": False},
            "value": {"type": "string", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

# Admin adds some records
records = admin.create_records(
    "secrets",
    [{"name": "admin-password", "value": "admin-password-value"}],
    expected_statuses=[201],
)


# Create a temporary policy for somebody
admin.create_policy(
    policy=Policy(
        policy_id="secret-access",
        effect="allow",
        actions=["read", "write"],
        resources=["/collections/secrets/*"],
    ),
    expected_statuses=[201, 409],
)

# Admin recreates somebody
admin.delete_principal(
    username=SOMEBODY_USERNAME,
    expected_statuses=[204, 404],
)

admin.create_principal(
    username=SOMEBODY_USERNAME,
    password=SOMEBODY_PASSWORD,
    description="somebody",
    policies=["secret-access"],
    expected_statuses=[201, 409],
)

somebody = Actor(VAULT_URL, SOMEBODY_USERNAME, SOMEBODY_PASSWORD)

# Somebody reads the records
record = somebody.get_record(
    collection="secrets",
    record_id=records[0],
    return_formats="name.plain,value.plain",
    expected_statuses=[200],
)

# Policy is removed
admin.delete_policy(
    policy_id="secret-access",
    expected_statuses=[204],
)

# Policy is removed twice for good measure
admin.delete_policy(
    policy_id="secret-access",
    expected_statuses=[404],
)

# Somebody can't read the records anymore
somebody.get_record(
    collection="secrets",
    record_id=records[0],
    return_formats="name.plain,value.plain",
    expected_statuses=[403],
)

# Admin deletes somebody
admin.delete_principal(
    username=SOMEBODY_USERNAME,
    expected_statuses=[204],
)

print("Ops use case completed successfully!")
