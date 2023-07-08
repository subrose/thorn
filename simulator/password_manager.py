from client import Actor

# VAULT_URL from your client.py
VAULT_URL = "http://localhost:3001"

# Step 0: Initialize your actors
admin = Actor(VAULT_URL, name="admin", access_key="admin", secret_key="admin")
admin.authenticate(expected_statuses=[200])

# Step 2: Create collection
admin.create_collection(
    schema={
        "name": "alice-passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

admin.create_collection(
    schema={
        "name": "bob-passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

# Step 3: Create policies using admin role
admin.create_policy(
    policy={
        "policy_id": "alice-read-own-passwords",
        "effect": "allow",
        "action": "read",
        "resource": "/collections/alice-passwords/*",
    },
    expected_statuses=[201, 409],
)

admin.create_policy(
    policy={
        "policy_id": "alice-write-own-passwords",
        "effect": "allow",
        "action": "write",
        "resource": "/collections/alice-passwords/*",
    },
    expected_statuses=[201, 409],
)


admin.create_policy(
    policy={
        "policy_id": "bob-read-own-passwords",
        "effect": "allow",
        "action": "read",
        "resource": "/collections/bob-passwords/*",
    },
    expected_statuses=[201, 409],
)

admin.create_policy(
    policy={
        "policy_id": "bob-write-own-passwords",
        "effect": "allow",
        "action": "write",
        "resource": "/collections/bob-passwords/*",
    },
    expected_statuses=[201, 409],
)

alice_res = admin.create_principal(
    "alice",
    "alice",
    ["alice-read-own-passwords", "alice-write-own-passwords"],
    expected_statuses=[201, 409],
)

assert alice_res is not None

alice = Actor(VAULT_URL, "alice", alice_res["access_key"], alice_res["access_secret"])
alice.authenticate(expected_statuses=[200])

bob_res = admin.create_principal(
    "bob", "bob", ["bob-read-own-passwords", "bob-write-own-passwords"]
)
assert bob_res is not None

bob = Actor(VAULT_URL, "bob", bob_res["access_key"], bob_res["access_secret"])
bob.authenticate(expected_statuses=[200])

# 2) Alice adds a password
alice_password = "alicerocks"
alice_password_res = alice.create_records(
    "alice-passwords",
    [{"service": "email", "password": alice_password}],
    expected_statuses=[201],
)

# 4) Bob adds a password
bob_password = "bobisthebest"
bob_password_res = bob.create_records(
    "bob-passwords",
    [{"service": "email", "password": bob_password}],
    expected_statuses=[201],
)

alice_password_id = alice_password_res[0]
bob_password_id = bob_password_res[0]

# 5) Alice views her passwords
alice_retrieved_password = alice.get_record(
    collection="alice-passwords",
    record_id=alice_password_id,
    format="plain",
    expected_statuses=[200],
)

assert alice_retrieved_password[alice_password_id]["password"] == alice_password

# 6) Bob views his passwords
bob_retrieved_password = bob.get_record(
    collection="bob-passwords",
    record_id=bob_password_id,
    format="plain",
    expected_statuses=[200],
)
assert bob_retrieved_password[bob_password_id]["password"] == bob_password

# 7) Alice can't CRUD Bob's passwords
alice.get_record(
    collection="bob-passwords",
    record_id=bob_password_id,
    format="plain",
    expected_statuses=[403],
)

# 8) Bob can't CRUD Alice's passwords
bob.get_record(
    collection="alice-passwords",
    record_id=alice_password_id,
    format="plain",
    expected_statuses=[403],
)

print("Password manager usecase ok!")
