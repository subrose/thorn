from client import Actor

# VAULT_URL from your client.py
VAULT_URL = "http://localhost:3000"

# Step 0: Initialize your actors
admin = Actor(VAULT_URL, "admin", "admin", "admin")
assert admin.authenticate() is True


# Step 2: Create collection
alice_collection = admin.create_collection(
    {
        "name": "alice-passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    }
)
bob_collection = admin.create_collection(
    {
        "name": "bob-passwords",
        "fields": {
            "service": {"type": "string", "indexed": False},
            "password": {"type": "string", "indexed": False},
        },
    }
)

# Step 3: Create policies using admin role
alice_read_policy = admin.create_policy(
    policy={
        "policy_id": "alice-read-own-passwords",
        "effect": "allow",
        "action": "read",
        "resource": "collections/alice-passwords/records",
    }
)

alice_write_policy = admin.create_policy(
    policy={
        "policy_id": "alice-write-own-passwords",
        "effect": "allow",
        "action": "write",
        "resource": "collections/alice-passwords/records",
    }
)

bob_read_policy = admin.create_policy(
    policy={
        "policy_id": "bob-read-own-passwords",
        "effect": "allow",
        "action": "read",
        "resource": "collections/bob-passwords/records",
    }
)

bob_write_policy = admin.create_policy(
    policy={
        "policy_id": "bob-write-own-passwords",
        "effect": "allow",
        "action": "write",
        "resource": "collections/bob-passwords/records",
    }
)

# 1) Change record resource from collections to records
# 2) Allow multiple actions and resources

alice_res = admin.create_principal(
    "alice", "alice", ["alice-read-own-passwords", "alice-write-own-passwords"]
)

if alice_res is None:
    raise Exception("Failed to create alice")

alice = Actor(VAULT_URL, "alice", alice_res["access_key"], alice_res["access_secret"])
alice.authenticate()

bob_res = admin.create_principal(
    "bob", "bob", ["bob-read-own-passwords", "bob-write-own-passwords"]
)

if bob_res is None:
    raise Exception("Failed to create bob")

bob = Actor(VAULT_URL, "bob", bob_res["access_key"], bob_res["access_secret"])
bob.authenticate()


# 2) Alice adds a password
alice_password = alice.create_records(
    "alice-passwords", [{"service": "email", "password": "alice_password_1"}]
)
if alice_password is None:
    raise Exception("Failed to create password for Alice")

# 4) Bob adds a password
bob_password = bob.create_records(
    "bob-passwords", [{"service": "email", "password": "bob_password_1"}]
)
if bob_password is None:
    raise Exception("Failed to create password for Bob")

# 5) Alice views her passwords
alice_passwords = alice.get_record("alice-passwords", alice_password[0])
if alice_passwords is None:
    raise Exception("Failed to get password for Alice")
print(f"Alice's passwords: {alice_passwords}")

# 6) Bob views his passwords
bob_passwords = bob.get_record("pbob-asswords", bob_password[0])
if bob_passwords is None:
    raise Exception("Failed to get password for Bob")
print(f"Bob's passwords: {bob_passwords}")

# 7) Alice can't CRUD Bob's passwords
try:
    alice_bob_password = alice.get_record("bob-passwords", "bob")
    if alice_bob_password is not None:
        raise Exception("Alice should not be able to access Bob's passwords")
except Exception as e:
    print(str(e))

# 8) Bob can't CRUD Alice's passwords
try:
    bob_alice_password = bob.get_record("alice-passwords", "alice")
    if bob_alice_password is not None:
        raise Exception("Bob should not be able to access Alice's passwords")
except Exception as e:
    print(str(e))
