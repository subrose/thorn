# Simulating a usecase of a simple ecommerce app
# Garden Inc is a flower ecommerce application that sells flowers online.

# They have the following requirements
# A backend application for processing orders, the PII it stores consists of:
# - Customer details
# -

# Create principals for company roles
# - Ecom Backend Service Account - This is the backend of the application
# - Marketing Team - These are persons on the marketing team that need access to customer
# - Customer Service Team
# - Admin

# Create collections
# - User collection with personal data and preferences
# - Credit Card collection


# Create policies
# - App policy - can read/write user & credit card collection
# - Marketing policy - can read email field from user collection only
# - Customer Service policy - can read/update email/phone field from user collection only


# Simulate application events
# 1) User signs up
# 2) User buys an apple with a credit card
# 3) Marketing need to engage with the user
# 4) Customer service need to update a user's email/phone
# 5) User requests a DSR
