# Password Manager

A secure and user-friendly password management application built with Electron. The app provides features for managing passwords, backing them up, and testing SSH-based login functionality.

## Features

- Secure password management with encryption.
- SSH-based login simulation for user authentication.
- Backup and restore functionality for your saved passwords.
- Easy-to-use dashboard interface with Material UI components.

## Installation and Setup

### Prerequisites

Ensure you have the following installed on your machine:

- Node.js (LTS version recommended)
- Electron

### Steps to Run the App

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd password-manager-electron
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Start the app:

   ```bash
   node main.js
   ```

## Using the App

### Logging In

- Use your ssh key to log in.
- Start the app and provide the SSH key when prompted.

### Adding a Password

- Navigate to the Dashboard.
- Click the "Add Password" button (the floating blue button at the bottom-right corner).
- Fill in the Username and Password fields.
- Click "Add Password" to save it.

### Backing Up Passwords

- On the dashboard, click the **Backup Passwords** button in the navbar.
- This will fetch and display your stored passwords, which can then be saved securely.

## API Endpoints

### 1. Add Password

- **Endpoint**: `POST /api/passwords`
- **Request Body**:

  ```json
  {
    "service": "Service Name",
    "username": "User Name",
    "password": "User Password"
  }
  ```

- **Response**:

  ```json
  {
    "success": true,
    "message": "Password added successfully",
    "_id": "Unique ID of the password"
  }
  ```

### 2. Fetch Passwords

- **Endpoint**: `POST /password/:username`
- **Request Body**:

  ```json
  {
    "Username": "Master Username",
    "MasterPassword": "Master Password"
  }
  ```

- **Response**:

  ```json
  {
    "passwords": [
      {
        "_id": "Unique ID",
        "description": "Service Name",
        "username": "User Name",
        "password": "Encrypted Password"
      }
    ]
  }
  ```

### 3. Delete Password

- **Endpoint**: `DELETE /api/passwords/:id`
- **Response**:

  ```json
  {
    "success": true,
    "message": "Password deleted successfully"
  }
  ```

## Screenshots

### Login Page

Add a screenshot of the login page here.

### Dashboard

Add a screenshot of the dashboard page here.

### Adding a New Password

Add a screenshot of the Add Password modal here.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

