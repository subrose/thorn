# Launch plan

Narrowing the featureset to get vault to a (0.1) state.

### Adhering to the followig:

1. Defer performance considerations
2. Only implement the bare basics of a privacy vault needed for compliance (No K anonymitiy)
3. Leverage the API we've built so far
4. Build for S2S

### Out of scope for 0.1:

- relationships, cascading deletes on records (with a relationship) and fields
- nested fields {"name": "xx", "addresses": [{"line1": "xx", "line2": "xx"}]}
- updating collections' schemas
- bulk operations
- complex policies
- DB Encryption\*
- Filtering & Indexing

### Keep as is:

- Basic auth
- Audit logs
- Policies
- PTypes
- Collections
- Principals

### Proposed changes:

- Record response model (to allow external data modelling, proposal below)
  - Records mostly stays as is, but inserted records return a unique ID per field
  - The unique ID can be used in an external db as a reference, this allows relationhip management externally
  - A new get method for fields allow retrieving a field by it's ID
- Remove encrypting DB records - this should be revised and done properly
  - This potentially needs to be done at a field level?
  - Rely on DB and VPC encryption
- Cloud SQL \*, solves: indexing, lookups, tokenisation storage, secure storage, cloud deployment

### Documentation

- Docs which contain:
  - Explanation of the vault
  - Fundamentals
  - Quick start
  - Section per concept (auth, collection, record, policy, principals)

### Blog posts

- Why use a privacy vault
- The data profileration problem
- How a privacy vault fits into standard architecture
- An follow along example + regulation - how to make users table GDPR compliant

### Distribute

- Post in a few places
- Demo and website (thorn.subrose.io)

### Records and fields API updates

<!-- Creating a record -->

POST /collections/<name>/records
Request body:

```
    {
        "name": "fld_123",
        "age": "fld_124"
        "gender": "fld_125"
    }
```

Response:

```
[
    {
        "id": "rec_12345",
        "fields": {
            "name": "tkn_123",
            "age": "tkn_124"
            "gender": "tkn_125"
        }
    }
]
```

| name    | age     | gender  |
| ------- | ------- | ------- |
| tkn_123 | tkn_124 | tkn_125 |

<!-- Get a record -->

POST /collections/<name>/record/<rec_id>?formats=<field>.<level>,...

```
{
    "name": "Paco",
    "age": "24"
    "gender": "M"
}
```

<!-- Get a field by token -->

GET /collections/<name>/tokens/<tkn_id>?format=<level>

```
    {
        "name": "Paco"
    }

```
