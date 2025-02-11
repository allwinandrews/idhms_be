from faker import Faker
import random
import json
from datetime import datetime, timedelta

# Initialize Faker
fake = Faker()

# Define possible roles and blood groups
roles = ["patient", "receptionist", "dentist"]
role_weights = [0.7, 0.2, 0.1]  # Weighted probabilities
blood_groups = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]

# Generate 30 random users
users = []
guardians = {}

for _ in range(30):
    # Assign random roles, ensuring uniqueness within the user
    num_roles = random.randint(1, len(roles))  # Random number of roles (1 to all roles)
    user_roles = random.sample(roles, k=num_roles)  # Select unique roles

    user = {
        "email": fake.unique.email(),
        "password": fake.password(length=10),
        "roles": user_roles,  # Assign multiple roles
        "blood_group": random.choice(blood_groups),
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "gender": random.choice(["Male", "Female", "Other"]),  # Match valid choices
        "dob": (datetime.now() - timedelta(days=random.randint(6570, 32850))).strftime(
            "%Y-%m-%d"
        ),  # Random age 18-90
        "phone_number": fake.phone_number(),
        "address": {
            "country": fake.country(),
            "state": fake.state(),
            "city": fake.city(),
            "street_address": fake.street_address(),
        },
    }

    # Assign guardian for dependents under 18
    if "patient" in user["roles"] and datetime.strptime(
        user["dob"], "%Y-%m-%d"
    ) > datetime.now() - timedelta(
        days=6570
    ):  # Under 18
        guardian_email = guardians.get("guardian_email", fake.unique.email())
        guardians[guardian_email] = {
            "email": guardian_email,
            "first_name": fake.first_name(),
            "last_name": fake.last_name(),
            "phone_number": fake.phone_number(),
        }
        user["guardian_email"] = guardian_email

    # Simulate missing or invalid data for testing
    if random.choice([True, False]):  # 50% chance of missing phone number
        user.pop("phone_number", None)

    users.append(user)

# Save the data as a JSON file (optional, for manual inspection)
with open("random_users.json", "w") as file:
    json.dump({"users": users}, file, indent=4)

# Print the data (for copying into Postman or other tools)
print(json.dumps({"users": users}, indent=4))
