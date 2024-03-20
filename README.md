# Hospital Management System

The Hospital Management System is a web-based application developed using Flask, which serves as a Role-Based Management System (RBMS) for managing hospital operations efficiently. The system allows for the management of doctors, nurses, and patients, with different levels of access and permissions based on their roles.

## Roles and Permissions

### Doctor
- Can view the entire information of nurses and patients assigned to them.

### Nurse
- Can view the entire information of patients assigned to them.
- Access restricted information about doctors assigned to them.

### Patient
- Can view restricted information about doctors and nurses assigned to them.

### Admin
- Has full access to all information in the system.
- Can add new doctors, nurses, and patients.
- Assigns roles and permissions to users.

## 
## Security Features

1. **Login**: Users are required to authenticate themselves using a username and password.
2. **Password Hashing**: Passwords are securely hashed before storing them in the database.
3. **RBMS**: Role-Based Management System ensures that users have appropriate access levels based on their roles.
4. **Two-Factor Authentication (2FA)**: Implemented using PyOTP for an additional layer of security.

## Usage

1. Clone the repository to your local machine.
2. Install the necessary dependencies in the requirement.txt using pip.
3. Run the Flask application.
4. Access the application through the provided credentials in login_pass.xlsx.
5. Explore the different functionalities based on your role.


