# Simulating a usecase of a simple ecommerce app
# Garden Inc is a flower ecommerce application that sells flowers online.

# They have the following requirements
# A backend application for processing orders, the PII it stores consists of:
# - Customer details
# - Credit card details

from client import Actor

VAULT_URL = "http://localhost:3000"

# Step 0: Initialize your actors
admin = Actor(VAULT_URL, "admin", "admin", "admin")
assert admin.authenticate()[0] is True

# Step 1: Create collections
_, status_code, error = admin.create_collection(
    {
        "name": "customer-collection",
        "fields": {
            "name": {"type": "string", "indexed": False},
            "email": {"type": "string", "indexed": False},
            "phone": {"type": "string", "indexed": False},
            "preferences": {"type": "string", "indexed": False},
        },
    }
)
if status_code not in [201, 409]:
    raise Exception(f"Failed to create collection: {status_code}, {error}")

_, status_code, error = admin.create_collection(
    {
        "name": "credit-card-collection",
        "fields": {
            "card_number": {"type": "string", "indexed": False},
            "expiry_date": {"type": "string", "indexed": False},
            "cvv": {"type": "string", "indexed": False},
        },
    }
)
if status_code not in [201, 409]:
    raise Exception(f"Failed to create collection: {status_code}, {error}")

# Step 2: Create policies
_, status_code, error = admin.create_policy(
    policy={
        "policy_id": "app-policy",
        "effect": "allow",
        "action": ["read", "write"],
        "resource": [
            "collections/customer-collection/*",
            "collections/credit-card-collection/*",
        ],
    }
)
if error:
    raise Exception(f"Failed to create policy: {error}")

_, status_code, error = admin.create_policy(
    policy={
        "policy_id": "marketing-policy",
        "effect": "allow",
        "action": "read",
        "resource": "collections/customer-collection/email",
    }
)
if error:
    raise Exception(f"Failed to create policy: {error}")

_, status_code, error = admin.create_policy(
    policy={
        "policy_id": "customer-service-policy",
        "effect": "allow",
        "action": ["read", "update"],
        "resource": [
            "collections/customer-collection/email",
            "collections/customer-collection/phone",
        ],
    }
)
if error:
    raise Exception(f"Failed to create policy: {error}")

# Step 3: Create principals
_, status_code, error = admin.create_principal(
    "ecom-backend-service", "ecom-backend-service", ["app-policy"]
)
if error:
    raise Exception("Failed to create ecom-backend-service: ", error)

_, status_code, error = admin.create_principal(
    "marketing-team", "marketing-team", ["marketing-policy"]
)
if error:
    raise Exception("Failed to create marketing-team: ", error)

_, status_code, error = admin.create_principal(
    "customer-service-team", "customer-service-team", ["customer-service-policy"]
)
if error:
    raise Exception("Failed to create customer-service-team: ", error)

# Step 4: Simulate application events
# 1) User signs up
# 2) User buys an apple with a credit card
# 3) Marketing need to engage with the user
# 4) Customer service need to update a user's email/phone
# 5) User requests a DSR
# ...


# Simulate application events
# 1) User signs up
# 2) User buys an apple with a credit card
# 3) Marketing need to engage with the user
# 4) Customer service need to update a user's email/phone
# 5) User requests a DSR
