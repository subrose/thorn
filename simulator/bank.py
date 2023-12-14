from client import Actor, init_client
from faker import Faker
from faker_e164.providers import E164Provider

vault_url = init_client()

admin = Actor(vault_url, username="admin", password="admin")
# Create collection
admin.create_collection(
    schema={
        "name": "employees",
        "type": "subject",
        "fields": {
            "soeid": {
                "type": "string",
                "is_indexed": False,
            },
            "geid": {
                "type": "string",
                "is_indexed": True,
            },
        },
    },
    expected_statuses=[201, 409],
)

admin.create_collection(
    schema={
        "name": "profiles",
        "type": "data",
        "parent": "employees",
        "fields": {
            "name": {
                "type": "string",
                "is_indexed": False,
            },
            "email": {
                "type": "email",
                "is_indexed": True,
            },
            "address": {
                "type": "address",
                "is_indexed": False,
            },
        },
    },
    expected_statuses=[201, 409],
)

fake = Faker()
fake.add_provider(E164Provider)

employees = [
    {
        "soeid": fake.e164(),
        "geid": fake.e164(),
        "name": fake.name(),
        "email": fake.email(),
        "address": fake.address(),
    }
    for _ in range(3)
]

for employee in employees:
    subject_id = admin.create_record(
        collection="employees",
        record={
            "soeid": employee["soeid"],
            "geid": employee["geid"],
        },
        expected_statuses=[201, 409],
    )

    # Ensure we can't add the same employee twice
    admin.create_record(
        collection="employees",
        record={
            "soeid": employee["soeid"],
            "geid": employee["geid"],
        },
        expected_statuses=[409],
    )

    admin.create_record(
        collection="profiles",
        record={
            "name": employee["name"],
            "email": employee["email"],
            "address": employee["address"],
            "subject_id": subject_id,
        },
        expected_statuses=[201, 409],
    )


# Now we can search for employees by their SOEID or GEID
search_ids_1 = admin.search_records(
    collection="employees",
    filters={"soeid": employees[0]["soeid"]},
    expected_statuses=[200],
)

# We can also search for employees by geid
search_ids_2 = admin.search_records(
    collection="employees",
    filters={"geid": employees[0]["geid"]},
    expected_statuses=[200],
)

# Or both at the same time
search_ids_3 = admin.search_records(
    collection="employees",
    filters={
        "soeid": employees[0]["soeid"],
        "geid": employees[0]["geid"],
    },
    expected_statuses=[200],
)
assert search_ids_1 == search_ids_2 == search_ids_3
assert len(search_ids_1) == 1

# Or both at the same time
profile_ids = admin.search_records(
    collection="profiles",
    filters={
        "subject_id": search_ids_1[0],
    },
    expected_statuses=[200],
)
profile_id = profile_ids[0]

admin.get_record(
    collection="profiles",
    record_id=profile_id,
    return_formats="name.plain",
    expected_statuses=[200],
)

admin.delete_record(
    collection="employees",
    record_id=search_ids_1[0],
    expected_statuses=[200],
)

admin.get_record(
    collection="profiles",
    record_id=profile_id,
    return_formats="name.plain",
    expected_statuses=[404],
)
