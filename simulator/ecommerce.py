# Simulating a usecase of a simple ecommerce app
# Garden Inc is a flower ecommerce application that sells flowers online.

# They have the following requirements
# A backend application for processing orders, the PII it stores consists of:
# - Customer details: name, email, phone
# - Credit card details

# Marketing team needs access to:
# - email:plain to send out marketing campaigns
# - name:plain to address users in marketing campaigns
# - phone:masked to understand where users are based (by analysing area codes)


from client import Actor

VAULT_URL = "http://localhost:3001"

# Step 0: Initialize your actors
admin = Actor(VAULT_URL, name="admin", access_key="admin", secret_key="admin")
admin.authenticate(expected_statuses=[200])

# Step 1: Create collections
_, status_code, error = admin.create_collection(
    schema={
        "name": "customers",
        "fields": {
            "name": {"type": "string", "indexed": False},
            "email": {"type": "string", "indexed": True},
            "phone": {"type": "string", "indexed": False},
            "credit-card": {"type": "credit-card", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

# Step 2: Create policies
admin.create_policy(
    policy={
        "id": "app",
        "effect": "allow",
        "actions": ["read", "write"],
        "resources": [
            "records/customers/*/*",  # all fields at all levels
        ],
    },
    expected_statuses=[201, 409],
)


admin.create_policy(
    policy={
        "id": "marketing",
        "effect": "allow",
        "action": ["read"],
        "resources": [
            "records/customers/email:plain",
            "records/customers/name:masked",
            "records/customers/phone:masked",
        ],
    },
    expected_statuses=[201, 409],
)

# Step 3: Create principals
ecomm_principal, _, _ = admin.create_principal(
    name="ecom-backend-service",
    description="ecom-backend-service",
    policies=["app"],
    expected_statuses=[201, 409],
)

marketing_principal, _, _ = admin.create_principal(
    name="marketing-team",
    description="marketing-team",
    policies=["marketing"],
    expected_statuses=[201, 409],
)

ecomm_backend = Actor(
    VAULT_URL,
    name="admin",
    access_key=ecomm_principal["access_key"],
    secret_key=ecomm_principal["secret_key"],
)
admin.authenticate(expected_statuses=[200])


# Step 4: Simulate application events
# 1) User signs up
# 2) User buys an apple with a credit card
# 3) Marketing need to engage with the user
