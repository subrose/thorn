from client import Actor

# VAULT_URL from your client.py
VAULT_URL = "http://localhost:3001"

# Step 0: Initialize your actors
admin = Actor(VAULT_URL, "admin", "admin", "admin")
assert admin.authenticate()[0] is True

# Step 2: Create collection
_, status_code, error = admin.create_collection(
    {
        "name": "alice-passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    }
)
if status_code not in [201, 409]:
    raise Exception(f"Failed to create collection: {status_code}, {error}")

_, status_code, error = admin.create_collection(
    {
        "name": "bob-passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    }
)

if status_code not in [201, 409]:
    raise Exception(f"Failed to create collection: {status_code}, {error}")


# Step 3: Create policies using admin role
_, status_code, error = admin.create_policy(
    policy={
        "policy_id": "alice-read-own-passwords",
        "effect": "allow",
        "action": "read",
        "resource": "collections/alice-passwords/*",
    }
)
if error:
    raise Exception(f"Failed to create policy: {error}")

_, status_code, error = admin.create_policy(
    policy={
        "policy_id": "alice-write-own-passwords",
        "effect": "allow",
        "action": "write",
        "resource": "collections/alice-passwords/*",
    }
)
if error:
    raise Exception(f"Failed to create policy: {error}")

_, status_code, error = admin.create_policy(
    policy={
        "policy_id": "bob-read-own-passwords",
        "effect": "allow",
        "action": "read",
        "resource": "collections/bob-passwords/*",
    }
)
if error:
    raise Exception(f"Failed to create policy: {error}")

_, status_code, error = admin.create_policy(
    policy={
        "policy_id": "bob-write-own-passwords",
        "effect": "allow",
        "action": "write",
        "resource": "collections/bob-passwords/*",
    }
)
if error:
    raise Exception(f"Failed to create policy: {error}")

# 1) Change record resource from collections to records
# 2) Allow multiple actions and resources

alice_res, status_code, error = admin.create_principal(
    "alice", "alice", ["alice-read-own-passwords", "alice-write-own-passwords"]
)

if error or alice_res is None:
    raise Exception("Failed to create alice: ", error)

alice = Actor(VAULT_URL, "alice", alice_res["access_key"], alice_res["access_secret"])
alice.authenticate()

bob_res, status_code, error = admin.create_principal(
    "bob", "bob", ["bob-read-own-passwords", "bob-write-own-passwords"]
)

if error or bob_res is None:
    raise Exception("Failed to create bob: ", error)

bob = Actor(VAULT_URL, "bob", bob_res["access_key"], bob_res["access_secret"])
bob.authenticate()

# 2) Alice adds a password
alice_password_res, status_code, error = alice.create_records(
    "alice-passwords", [{"service": "email", "password": "alice_password_1"}]
)
if error or alice_password_res is None:
    raise Exception("Failed to create password for Alice: ", error)

# 4) Bob adds a password
bob_password_res, status_code, error = bob.create_records(
    "bob-passwords", [{"service": "email", "password": "bob_password_1"}]
)
if error or bob_password_res is None:
    raise Exception("Failed to create password for Bob: ", error)

alice_password_id = alice_password_res[0]
bob_password_id = bob_password_res[0]

# 5) Alice views her passwords
_, status_code, error = alice.get_record("alice-passwords", alice_password_id)
if error:
    raise Exception("Failed to get password for Alice: " + error)

# 6) Bob views his passwords
_, status_code, error = bob.get_record("bob-passwords", bob_password_id)
if error:
    raise Exception("Failed to get password for Bob: " + error)

# 7) Alice can't CRUD Bob's passwords
_, status_code, error = alice.get_record("bob-passwords", bob_password_id)
if not error:
    raise Exception("Alice should not be able to access Bob's passwords")

# 8) Bob can't CRUD Alice's passwords
_, status_code, error = bob.get_record("alice-passwords", alice_password_id)
if not error:
    raise Exception("Bob should not be able to access Alice's passwords")
