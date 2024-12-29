# Intelligent Dental Hospital Management System Backend (IDHMS_BE)

This project serves as the backend for the **Intelligent Dental Hospital Management System (IDHMS)**, providing robust APIs for user management, role-based access control, appointment handling, and more. Built with Django and PostgreSQL, this backend ensures scalability, security, and efficiency.

---

## Features

- **User Management:**

  - Role-based access control (`Admin`, `Receptionist`, `Dentist`, `Patient`).
  - Support for multiple roles per user.
  - Guardian assignment for dependent patients.

- **Appointment Management:**

  - CRUD operations for appointments.
  - Patients can view their appointments.
  - Receptionists manage appointments.

- **Authentication:**

  - Secure token-based authentication with JWT.
  - Role-specific endpoints for fine-grained access control.

- **Billing and History:**
  - Track patient billing and appointment history.
  - Support for custom data validations.

---

## Prerequisites

Before setting up the backend, ensure you have the following installed:

- Python 3.9+
- PostgreSQL
- Git

---

## Setup and Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/allwinandrews/idhms_be.git
   cd idhms_be
   ```

2. **Set Up a Virtual Environment:**

   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure the Database:**
   Update the `settings.py` with your PostgreSQL credentials:

   ```python
   DATABASES = {
       'default': {
           'ENGINE': 'django.db.backends.postgresql',
           'NAME': 'idhms_db',
           'USER': 'your_username',
           'PASSWORD': 'your_password',
           'HOST': 'localhost',
           'PORT': '5432',
       }
   }
   ```

5. **Run Database Migrations:**

   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Initialize Superuser:**
   ```bash
   python manage.py createsuperuser
   ```

---

## Usage

### Running the Development Server

Start the Django development server:

```bash
python manage.py runserver
```

### Database Initialization

Run the script to initialize the database:

```bash
python main.py
```

---

## Testing

Run all tests using `pytest`:

```bash
pytest api/tests/
```

---

## API Endpoints

### Authentication

- **POST** `/api/login/` - Login to retrieve JWT tokens.
- **POST** `/api/register/` - Register new users.

### Appointments

- **GET/POST** `/api/appointments/` - List or create appointments.
- **GET/PUT/DELETE** `/api/appointments/<int:id>/` - Retrieve, update, or delete an appointment.

### User Management

- **GET** `/api/users/` - List all users (Admin-only).
- **GET/PUT/DELETE** `/api/users/<int:id>/` - Manage specific users.

### Additional Endpoints

- **GET** `/api/secure/` - A secure endpoint for testing authentication.

---

## Administration

To access the admin panel:

1. Run the server.
2. Visit [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/).
3. Use the superuser credentials:
   - **Username:** `admin`
   - **Password:** `Omgomg@admin333`

### Deleting Superuser via Shell

```bash
python manage.py shell
from django.contrib.auth import get_user_model
model = get_user_model()
model.objects.get(username="admin", is_superuser=True).delete()
exit()
```

---

## Deployment

### Update Requirements

If you add dependencies:

```bash
pip freeze > requirements.txt
```

### PostgreSQL Setup

Connect to the PostgreSQL database:

```bash
psql -U postgres -h localhost
```

---

## Contributing

We welcome contributions! To get started:

1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
