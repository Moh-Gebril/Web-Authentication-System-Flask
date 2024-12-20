# Flask Authentication System

A secure, production-ready Flask authentication system with role-based access control and session management.

## Features

- 🔐 Secure user authentication with PBKDF2-SHA256 password hashing
- 👥 Role-based access control (Admin and User roles)
- 🔒 Server-side session management with Redis
- 🛡️ Rate limiting on sensitive endpoints
- 🐳 Docker containerization
- 📝 Comprehensive error handling and logging
- 🔑 UUID-based user identification
- 🍪 Secure session cookie configuration
- ⚡ PostgreSQL database with SQLAlchemy ORM

## Tech Stack

- Flask
- PostgreSQL
- Redis
- Docker
- SQLAlchemy
- Flask-Limiter
- Werkzeug Security

## Prerequisites

- Docker and Docker Compose
- Python 3.8+
- PostgreSQL 15+
- Redis

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Moh-Gebril/Web-Authentication-System-Flask.git
cd Web-Authentication-System-Flask
```

2. Create a `.env` file:

```bash
SECRET_KEY=your_secret_key
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=postgres
```

3. Build and run with Docker Compose:

```bash
docker-compose up --build
```

The application will be available at `http://localhost:4000`.

## API Endpoints

# User Authentication and Management API

This is a Flask-based API for user authentication and management. It includes routes for:
- User registration and login
- Session management
- User profile management
- Role-based access control
- Rate limiting on sensitive endpoints

## Requirements

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-Limiter
- werkzeug
- SQLAlchemy

## Setup

1. Clone the repository:
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

2. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Configure the environment:
    - Set up your database and other configuration variables in the `config.py` file.

4. Run the Flask application:
    ```bash
    python app.py
    ```

## API Endpoints

### `GET /test`
A test route to verify authentication and rate limiting.
- **Rate limit:** 5 requests per minute
- **Authentication:** Required
- **Response:**
    - `200 OK`: Success
    - `401 Unauthorized`: User is not authenticated
    - `429 Too Many Requests`: Rate limit exceeded

### `GET /@me`
Get the currently authenticated user's profile.
- **Authentication:** Required (based on session)
- **Response:**
    - `200 OK`: Returns the user's profile data (username, email)
    - `401 Unauthorized`: User is not authenticated
    - `500 Internal Server Error`: Database error or server issue

### `POST /register`
Register a new user in the system.
- **Rate limit:** 10 requests per minute
- **Expected request body:**
    ```json
    {
        "username": "string",
        "email": "string",
        "password": "string",
        "role": "string"  // "admin" or "user"
    }
    ```
- **Response:**
    - `201 Created`: User created successfully
    - `400 Bad Request`: Invalid input data
    - `409 Conflict`: User already exists
    - `429 Too Many Requests`: Rate limit exceeded
    - `500 Internal Server Error`: Server error or database issue

### `POST /login`
Login an existing user.
- **Rate limit:** 10 requests per minute
- **Expected request body:**
    ```json
    {
        "email": "string",
        "password": "string"
    }
    ```
- **Response:**
    - `200 OK`: Successful login, returns user session token
    - `400 Bad Request`: Invalid input data
    - `401 Unauthorized`: Incorrect email or password
    - `429 Too Many Requests`: Rate limit exceeded
    - `500 Internal Server Error`: Server or database issue

### `POST /logout`
Logout the current user and terminate their session.
- **Response:**
    - `200 OK`: Successful logout
    - `500 Internal Server Error`: Server issue

## Rate Limiting

The API uses Flask-Limiter to implement rate limiting. The following limits apply:
- `5 requests per minute` for the `/test` route
- `10 requests per minute` for `/register` and `/login`

## Authentication

This API uses session-based authentication for user login and profile management. Upon successful login, the server creates a session and stores the user's ID. This session ID is used to authenticate subsequent requests.

## Role-Based Access Control

Users can be assigned the following roles:
- `admin`: Has access to all routes and admin-specific functionality
- `user`: Regular user with limited access

Admin routes are protected and can only be accessed by users with the `admin` role.

## Error Handling

The API provides error responses with appropriate status codes and messages:
- `400 Bad Request`: Invalid or incomplete data in the request
- `401 Unauthorized`: Authentication required or invalid credentials
- `403 Forbidden`: Insufficient permissions to access the requested resource
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server or database error

## Logging

Logging is enabled for error handling and monitoring purposes. Errors are logged with detailed information for debugging.

## Security Features

- **Password Security**: Uses PBKDF2-SHA256 for password hashing
- **Session Management**: Server-side sessions stored in Redis
- **Rate Limiting**: Prevents brute force attacks
- **CSRF Protection**: Enabled in production
- **Secure Cookies**: HTTPOnly, SameSite, and secure flags
- **Role-Based Access**: Admin and user role separation

## Development

1. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate  # Windows
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run tests:

```bash
docker-compose run test
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Important Notes for Production Environment

**Security Consideration for User Registration**

Currently, the API allows any user to register an admin account. This is intended for the development environment, where we may want to test admin functionality easily. However, **in a production environment, this behavior should be removed** to prevent unauthorized users from assigning themselves admin roles.

### Modifications for Production

For production use, the role assignment during user registration should be restricted:
- The default role for new users should be `user` (normal user).
- Only users with the `admin` role should be allowed to register accounts with the `admin` role.

This restriction can be implemented by:
1. Removing the ability for normal users to register an admin account.
2. Ensuring that only authenticated users with the `admin` role can assign the `admin` role during the registration process.

Make sure to update the registration logic to enforce this security control before deploying the API to a production environment.

