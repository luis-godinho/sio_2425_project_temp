# SIO Project - Delivery 2

## Team members

- **Luis Godinho** 112959
- **Tiago Lopes** 113586
- **José Marques** 114321

## Features Implemented

### 1.Security

#### Session

- When creating a session it is sent a password that is encrypted and stored in the database
- When there is the need for a session, it is sent the session id and the password, then the repository validates the password and the session itself

#### Messages

- When the client sends a request, the request is encrypted using the repository's public key, when receiving the request decrypts the message with its private key, which is loaded as soon as the repository is started.
- When the repository sends a response, if the session is valid, uses the current session's user public key to encrypt the data and when receiving that data, the client is prompted to provide a password so its private key can be loaded to decrypt the response.

#### Protection

- When sending a message from either the client or the repository, if the message is encrypted, a timestamp is added to the message, which is going to be checked when decrypting, if the diference in time is higher than the defined time threshold, the message is going to be invalidated, in order to protect against Replay attacks.
- A checksum is calculated and added to the message before encryption, upon receiving and decrypting a checksum of the message is calculated and compared to the already calculated one, when the values don't match, the message is invalidated, in order to protect against manipulation attacks.

### 2. API Endpoints

- **`/organization/create` (POST)**

  - When creating the organization now the user who creates has the **Manager** role added to him, with all the existing permissions

- **`/subject/list` (GET)**

  - Now returns the status of the subject.

- **`/permission/roles` (GET)**

  - Receives a permissions checks if it is a valid permission, if it is, finds all roles, of the organization related to the session, that contain the given permission

- **`/document/list` (GET)**

  - Fixed date filter, now filters given the flags (nt, ot, et)

- **`/document/metadata` (GET)**

  - Now sends the alg and key used to encrypt the file, both of these encrypted.

- **`/role/add` (POST)**

  - Creates a new role for the organization which the client has a session with, if the role does not exist. The permission **ROLE_NEW** is checked for the current role the client has in the session before creating the role.

- **`/role/assume` (POST)**

  - Assumes the given role, if the organization which the client has a session with contains the role.

- **`/role/drop` (POST)**

  - Drops role, if it is equal to the current role in the session.

- **`/roles` (GET)**

  - Lists all the roles in the organization the client has a session with.

- **`/role/subject` (GET)**

  - Given a role, lists all subjects that have that role in the organization the client has a session with.

- **`/permission/add` (POST)**

  - Checks whether the last argument is a permission or a username, by comparing to a list of reserved names, if it is a permission it is added to the given role, otherwise, if there is any user with the given username is present in the organization the role is added to that user

- **`/permission/remove` (POST)**

  - Checks whether the last argument is a permission or a username, by comparing to a list of reserved names, if it is a permission it is removed of the given role, otherwise, if there is any user with the given username is present in the organization the role is removed of that user

- **`/document/acl` (POST)**

  - This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role.

- **`/role/permission` (GET)**

  - Given a role, if the role exists in the organization it lists all its permission

- **`/role/suspend` (POST)**

  - Suspends a role, if it is not the **Manager** role.

- **`/role/activate` (POST)**

  - Reactivates a suspended role.

- **`/subject/role` (GET)**

  - Given a valid subject it lists all roles that subject has in the organization the client has a session with
