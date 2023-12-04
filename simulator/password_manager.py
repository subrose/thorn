from client import Actor, Policy, init_client

vault_url = init_client()
# Step 0: Initialize your actors

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

ALICE_USERNAME = "alice"
ALICE_PASSWORD = "alice-password"

BOB_USERNAME = "bob"
BOB_PASSWORD = "bob-password"


admin = Actor(vault_url, username=ADMIN_USERNAME, password=ADMIN_PASSWORD)

# Step 2: Create collection
admin.create_collection(
    schema={
        "name": "alice_passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

admin.create_collection(
    schema={
        "name": "bob_passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

# Step 3: Create policies using admin role

alice_policy = admin.create_policy(
    policy=Policy(
        effect="allow",
        actions=["read", "write"],
        resources=["/collections/alice_passwords/*"],
    ),
    expected_statuses=[201, 409],
)


bob_policy = admin.create_policy(
    policy=Policy(
        effect="allow",
        actions=["read", "write"],
        resources=["/collections/bob_passwords/*"],
    ),
    expected_statuses=[201, 409],
)

admin.create_principal(
    username=ALICE_USERNAME,
    password=ALICE_PASSWORD,
    description="alice",
    policies=[alice_policy["id"]],
    expected_statuses=[201, 409],
)


alice = Actor(vault_url, ALICE_USERNAME, ALICE_PASSWORD)

admin.create_principal(
    username=BOB_USERNAME,
    password=BOB_PASSWORD,
    description="bob",
    policies=[bob_policy["id"]],
    expected_statuses=[201, 409],
)

bob = Actor(vault_url, BOB_USERNAME, BOB_PASSWORD)

# 2) Alice adds a password
alice_password = "alicerocks"
alice_password_res = alice.create_records(
    "alice_passwords",
    [{"service": "email", "password": alice_password}],
    expected_statuses=[201],
)

# 4) Bob adds a password
bob_password = "bobisthebest"
bob_password_res = bob.create_records(
    "bob_passwords",
    [{"service": "email", "password": bob_password}],
    expected_statuses=[201],
)

alice_password_id = alice_password_res[0]
bob_password_id = bob_password_res[0]

# 5) Alice views her passwords
alice_retrieved_password = alice.get_record(
    collection="alice_passwords",
    record_id=alice_password_id,
    return_formats="service.plain,password.plain",
    expected_statuses=[200],
)

assert alice_retrieved_password[alice_password_id]["password"] == alice_password

# 6) Bob views his passwords
bob_retrieved_password = bob.get_record(
    collection="bob_passwords",
    record_id=bob_password_id,
    return_formats="service.plain,password.plain",
    expected_statuses=[200],
)
assert bob_retrieved_password[bob_password_id]["password"] == bob_password

# 7) Alice can't CRUD Bob's passwords
alice.get_record(
    collection="bob_passwords",
    record_id=bob_password_id,
    return_formats="service.plain,password.plain",
    expected_statuses=[403],
)

# 8) Bob can't CRUD Alice's passwords
bob.get_record(
    collection="alice_passwords",
    record_id=alice_password_id,
    return_formats="service.plain,password.plain",
    expected_statuses=[403],
)

print("Password manager usecase ok!")
