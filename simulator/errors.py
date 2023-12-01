import requests

admin_session = requests.Session()
admin_session.auth = ("admin", "admin")

res = admin_session.post(
    "http://localhost:3001/policies",
    json={
        "additionalProperties": False,
        "policy_id": "secret-access",
        "effect": "allow",
        "actions": ["read", "write"],
        "resources": ["/collections/secrets/*"],
    },
)


print(res.status_code)
print(res.json())
