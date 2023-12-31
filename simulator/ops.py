from client import Actor, Policy, init_client

vault_url = init_client()
# Step 0: Initialize your actors

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

SOMEBODY_USERNAME = "somebody"
SOMEBODY_PASSWORD = "somebody-password"

admin = Actor(vault_url, username=ADMIN_USERNAME, password=ADMIN_PASSWORD)

#  Create collection and some records
admin.create_collection(
    schema={
        "name": "secrets",
        "fields": {
            "name": {
                "type": "string",
                "is_indexed": False,
            },
            "value": {
                "type": "string",
                "is_indexed": False,
            },
        },
    },
    expected_statuses=[201, 409],
)

# Admin adds some records
record_id = admin.create_record(
    "secrets",
    {"name": "admin-password", "value": "admin-password-value"},
    expected_statuses=[201],
)


# Create a temporary policy for somebody
temp_policy = admin.create_policy(
    policy=Policy(
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
    policies=[temp_policy["id"]],
    expected_statuses=[201, 409],
)

somebody = Actor(vault_url, SOMEBODY_USERNAME, SOMEBODY_PASSWORD)

# Somebody reads the records
record = somebody.get_record(
    collection="secrets",
    record_id=record_id,
    return_formats="name.plain,value.plain",
    expected_statuses=[200],
)

# Policy is removed
admin.delete_policy(
    policy_id=temp_policy["id"],
    expected_statuses=[204],
)

# Policy is removed twice for good measure
admin.delete_policy(
    policy_id=temp_policy["id"],
    expected_statuses=[404],
)

# Somebody can't read the records anymore
somebody.get_record(
    collection="secrets",
    record_id=record_id,
    return_formats="name.plain,value.plain",
    expected_statuses=[403],
)

# Admin deletes somebody
admin.delete_principal(
    username=SOMEBODY_USERNAME,
    expected_statuses=[204],
)

print("Ops use case completed successfully!")
