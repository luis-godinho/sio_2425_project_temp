import argparse
import base64
import getpass
import json
import os
from urllib.parse import quote

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptographer import decrypt, decrypt_json, encrypt_json

try:
    with open("../RepoKeys/Repo.pem.pub", "r") as f:
        REP_PUB_KEY = f.read()
except:
    pass

REP_ADDRESS = "127.0.0.1:5000"


def get_private_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        pem_data = key_file.read()

        while (password := getpass.getpass("private key password: ")) == "":
            continue
        try:
            private_key = load_pem_private_key(
                pem_data, password=password.encode(), backend=default_backend()
            )
        except:
            print("Wrong password. Unable to complete request.")
            exit(1)
        return private_key


def get_session_info(session_file):
    with open(session_file, "r") as s_file:
        session = s_file.read()
        session_data = json.loads(session)
        session_info = {"id": session_data["session_id"], "password": session_data["password"]}
        private_key_path = session_data["private_key_path"]
        private_key = get_private_key(private_key_path)
        return session_info, private_key


def url_encode(data):
    data_encrypted = encrypt_json(data, REP_PUB_KEY)
    encoded_message = quote(data_encrypted[0].encode())

    return encoded_message


def get_message_code(res, private_key=None):
    response, code = res
    try:
        if private_key:
            response, code = (
                decrypt_json(res[0], private_key),
                res[1]
            )
    except:
        print(res)
        return -1

    if code >= 400:
        print(response)
        return -1

    return response


# Local commands


def rep_subject_credentials(password, credential_file):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )

    with open(credential_file, "wb") as file:
        file.write(encrypted_private_key)
        print(f"Private key saved at {file.name}")

    with open(credential_file + ".pub", "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        print(f"Public key saved at {file.name}")
    return 0


def rep_decrypt_file(encrypted_file_path, metadata_path):
    with open(metadata_path, "r") as metadata_file:
        metadata_content = metadata_file.read().replace("'", '"')
        try:
            metadata = json.loads(metadata_content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in metadata file: {e}")

    algorithm = base64.b64decode(metadata.get("alg"))
    wrapped_key = base64.b64decode(metadata.get("wrapped_key"))

    if not algorithm or not wrapped_key:
        raise ValueError(
            "Metadata file is missing required fields 'alg' or 'wrapped_key'."
        )

    with open(encrypted_file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    decrypted_data = decrypt(encrypted_data, wrapped_key, algorithm)

    base, ext = os.path.splitext(encrypted_file_path)
    if ext:
        decrypted_file_path = f"{base}_decrypted{ext}"
    else:
        decrypted_file_path = encrypted_file_path + "_decrypted"
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    return decrypted_file_path


# Commands that use the anonymous API


def rep_create_org(organization, username, name, email, pub_key_file):
    with open(pub_key_file, "r") as file:
        public_key = file.read()

    data = {
        "organization": organization,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
    }

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/organization/create", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res)
    if message == -1:
        return -1

    for doc in message:
        print(doc)

    return 0


def rep_list_orgs():
    response = requests.get(f"http://{REP_ADDRESS}/organization/list")

    res = json.loads(response.content.decode())

    message = get_message_code(res)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_create_session(organization, username, password, credential_file, session_file):
    with open(credential_file, "r") as file:
        public_key = file.read()

    private_key = get_private_key(credential_file.replace(".pub", ""))

    data = {
        "organization": organization,
        "username": username,
        "password": password,
        "creds": public_key,
    }

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/session/create", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    with open(session_file, "w") as file:
        message["private_key_path"] = credential_file.replace(".pub", "")
        message["password"] = password
        file.write(json.dumps(message))

    return 0


def rep_get_file(file_handle, file=None):
    response = requests.get(f"http://{REP_ADDRESS}/file/download/{file_handle}")
    res = json.loads(response.content.decode())
    response, code = base64.b64decode(res[0]), res[1]

    if code != 200:
        print(res)
        return -1

    if file:
        with open(file, "wb") as output:
            output.write(response)
    else:
        print(response)

    return 0


# Commands that use the authenticated API


def rep_assume_role(session_file, role):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "role": role}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/role/assume", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_drop_role(session_file, role):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "role": role}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/role/drop", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_list_roles(session_file, role):
    session_info, private_key = get_session_info(session_file)

    session_encoded = url_encode(session_info)

    response = requests.get(f"http://{REP_ADDRESS}/roles?session={session_encoded}")

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    for role in message:
        print(role)

    return 0


def rep_list_subjects(session_file, username=None):
    session_info, private_key = get_session_info(session_file)

    encoded_session = url_encode(session_info)

    url = f"http://{REP_ADDRESS}/subject/list?session={encoded_session}"
    if username:
        encoded_username = url_encode(username)
        url += f"&username={encoded_username}"
    response = requests.get(url)

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    for subject in message:
        print(
            f"Username: {subject['username']}, Name: {subject['full_name']}, Email: {subject['email']}, Id: {subject['subject_id']}, Status: {subject['status']}"
        )

    return 0


def rep_list_role_subjects(session_file, role):
    session_info, private_key = get_session_info(session_file)

    session_encoded = url_encode(session_info)
    role_encoded = url_encode(role)

    url = f"http://{REP_ADDRESS}/role/subject?session={session_encoded}&role={role_encoded}"

    response = requests.get(url)

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    for role in message:
        print(role)

    return 0


def rep_list_subject_roles(session_file, username):
    session_info, private_key = get_session_info(session_file)

    session_encoded = url_encode(session_info)
    role_encoded = url_encode(username)

    url = f"http://{REP_ADDRESS}/subject/role?session={session_encoded}&subject={role_encoded}"
    response = requests.get(url)

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    for role in message:
        print(role)

    return 0


def rep_list_role_permissions(session_file, role):
    session_info, private_key = get_session_info(session_file)

    session_encoded = url_encode(session_info)
    role_encoded = url_encode(role)
    url = f"http://{REP_ADDRESS}/role/permission?session={session_encoded}&role={role_encoded}"

    response = requests.get(url)

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    for role in message.get("permissions"):
        print(role)

    return 0


def rep_list_permission_roles(session_file, permission):
    session_info, private_key = get_session_info(session_file)

    session_encoded = url_encode(session_info)
    permission_encoded = url_encode(permission)

    response = requests.get(
        f"http://{REP_ADDRESS}/permission/roles?session={session_encoded}&permission={permission_encoded}"
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    for role in message:
        print(role)

    return 0


def rep_list_docs(session_file, username=None, date=None):
    session_info, private_key = get_session_info(session_file)

    encoded_session = url_encode(session_info)

    url = f"http://{REP_ADDRESS}/document/list?session={encoded_session}"
    if username:
        username_encoded = url_encode(username)
        url += f"&username={username_encoded}"
    if date:
        date_encoded = url_encode(date)
        url += f"&date={date_encoded}"

    response = requests.get(url)

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    for d in message:
        print(d)

    return 0


# Commands that use the authorized API


def rep_add_subject(session_file, username, name, email, credential_file):
    session_info, private_key = get_session_info(session_file)

    with open(credential_file, "r") as file:
        public_key = file.read()

    data = {
        "session": session_info,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
    }

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/subject/add", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_suspend_subject(session_file, username):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "username": username}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/subject/suspend", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_activate_subject(session_file, username):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "username": username}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/subject/activate", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_add_role(session_file, role):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "role": role}

    message = encrypt_json(data, REP_PUB_KEY)

    response_encrypted = requests.post(
        f"http://{REP_ADDRESS}/role/add", json=json.dumps(message)
    )

    res = json.loads(response_encrypted.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_suspend_role(session_file, role):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "role": role}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/role/suspend", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_reactivate_role(session_file, role):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "role": role}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/role/activate", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_add_permission(session_file, role, username_or_permission):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "role": role, "perm": username_or_permission}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/permission/add", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_remove_permission(session_file, role, username_or_permission):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "role": role, "perm": username_or_permission}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/permission/remove", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_add_doc(session_file, document_name, file):
    session_info, private_key = get_session_info(session_file)

    with open(file, "r") as doc:
        file_content = doc.read()

    data = {"session": session_info, "doc_name": document_name, "file": file_content}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/document/add", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_get_doc_metadata(session_file, document_name):
    session_info, private_key = get_session_info(session_file)

    encoded_session = url_encode(session_info)
    encoded_doc = url_encode(document_name)

    response = requests.get(
        f"http://{REP_ADDRESS}/document/metadata?session={encoded_session}&doc_name={encoded_doc}"
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_get_doc_file(session_file, document_name, file=None):
    session_info, private_key = get_session_info(session_file)

    encoded_session = url_encode(session_info)
    encoded_doc = url_encode(document_name)

    response = requests.get(
        f"http://{REP_ADDRESS}/document/getfile?session={encoded_session}&doc_name={encoded_doc}"
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    if file:
        with open(file, "wb") as output:
            output.write(message)
    else:
        print(message)

    return 0


def rep_delete_doc(session_file, document_name):
    session_info, private_key = get_session_info(session_file)

    data = {"session": session_info, "doc_name": document_name}

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/document/delete", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def rep_acl_doc(session_file, document_name, operation, role, permission):
    session_info, private_key = get_session_info(session_file)

    data = {
        "session": session_info,
        "doc": document_name,
        "op": operation,
        "role": role,
        "perm": permission,
    }

    message = encrypt_json(data, REP_PUB_KEY)

    response = requests.post(
        f"http://{REP_ADDRESS}/document/acl", json=json.dumps(message)
    )

    res = json.loads(response.content.decode())

    message = get_message_code(res, private_key)
    if message == -1:
        return -1

    print(message)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Manage organizations, sessions, and files"
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Commands")

    # Subparser: rep_subject_credentials
    parser_subject_credentials = subparsers.add_parser(
        "rep_subject_credentials",
        help="Generate and save subject credentials (private/public keys)",
    )
    parser_subject_credentials.add_argument(
        "password", type=str, help="Password to encrypt the private key"
    )
    parser_subject_credentials.add_argument(
        "credential_file", type=str, help="File path to save credentials"
    )

    # Subparser: rep_decrypt_file
    parser_decrypt_file = subparsers.add_parser(
        "rep_decrypt_file", help="Decrypt a file using its metadata"
    )
    parser_decrypt_file.add_argument(
        "encrypted_file_path", type=str, help="Path to the encrypted file"
    )
    parser_decrypt_file.add_argument(
        "metadata_path", type=str, help="Path to the metadata file"
    )

    # Subparser: rep_create_org
    parser_create_org = subparsers.add_parser(
        "rep_create_org", help="Create an organization"
    )
    parser_create_org.add_argument(
        "organization", type=str, help="Name of the organization"
    )
    parser_create_org.add_argument("username", type=str, help="Username")
    parser_create_org.add_argument("name", type=str, help="Name of the user")
    parser_create_org.add_argument("email", type=str, help="Email of the user")
    parser_create_org.add_argument(
        "pub_key_file", type=str, help="Path to the public key file"
    )

    # Subparser: rep_list_orgs
    parser_list_orgs = subparsers.add_parser(
        "rep_list_orgs", help="List all organizations"
    )

    # Subparser: rep_create_session
    parser_create_session = subparsers.add_parser(
        "rep_create_session", help="Create a session"
    )
    parser_create_session.add_argument(
        "organization", type=str, help="Name of the organization"
    )
    parser_create_session.add_argument("username", type=str, help="Username")
    parser_create_session.add_argument("password", type=str, help="Password")
    parser_create_session.add_argument(
        "credential_file", type=str, help="Path to the credential file"
    )
    parser_create_session.add_argument(
        "session_file", type=str, help="Path to save the session file"
    )

    # Subparser: rep_get_file
    parser_get_file = subparsers.add_parser(
        "rep_get_file", help="Retrieve a file using its handle"
    )
    parser_get_file.add_argument(
        "file_handle", type=str, help="The handle of the file to retrieve"
    )
    parser_get_file.add_argument(
        "--file", "-f", type=str, help="Optional path to save the file", required=False
    )

    # Subparser: rep_assume_role
    parser_assume_role = subparsers.add_parser(
        "rep_assume_role", help="Request a role for the session"
    )
    parser_assume_role.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_assume_role.add_argument("role", type=str, help="Role name")

    # Subparser: rep_drop_role
    parser_drop_role = subparsers.add_parser(
        "rep_drop_role", help="Release the role for the session"
    )
    parser_drop_role.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_drop_role.add_argument("role", type=str, help="Role name")

    # Subparser: rep_list_roles
    parser_list_roles = subparsers.add_parser(
        "rep_list_roles", help="List current session roles"
    )
    parser_list_roles.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_list_roles.add_argument("role", type=str, help="Role name")

    # Subparser: rep_list_subjects
    parser_list_subjects = subparsers.add_parser(
        "rep_list_subjects", help="List all subjects or filter by username"
    )
    parser_list_subjects.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_list_subjects.add_argument(
        "--username", "-u", type=str, help="Filter by username", required=False
    )

    # Subparser: rep_list_role_subjects
    parser_list_role_subjects = subparsers.add_parser(
        "rep_list_role_subjects", help="List the subjects of a role of the organization"
    )

    parser_list_role_subjects.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_list_role_subjects.add_argument("role", type=str, help="Role name")

    # Subparser: rep_list_subject_roles
    parser_list_subject_roles = subparsers.add_parser(
        "rep_list_subject_roles", help="List the roles of a subject of the organization"
    )
    parser_list_subject_roles.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_list_subject_roles.add_argument(
        "username", type=str, help="Filter by username"
    )

    # Subparser: rep_list_role_permissions
    parser_list_role_permissions = subparsers.add_parser(
        "rep_list_role_permissions",
        help="List the permissions of a role of the organization",
    )
    parser_list_role_permissions.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_list_role_permissions.add_argument("role", type=str, help="Role name")

    # Subparser: rep_list_permission_roles
    parser_list_permission_roles = subparsers.add_parser(
        "rep_list_permission_roles",
        help="List the roles of the organization in the session that have a given permission",
    )
    parser_list_permission_roles.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_list_permission_roles.add_argument(
        "permission", type=str, help="Permission name"
    )

    # Subparser: rep_list_docs
    parser_list_docs = subparsers.add_parser(
        "rep_list_docs", help="List all documents or filter by username and/or date"
    )
    parser_list_docs.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_list_docs.add_argument(
        "--username", "-s", type=str, help="Filter by username", required=False
    )
    parser_list_docs.add_argument(
        "--date",
        "-d",
        nargs=2,
        help="Filter by date (nt/ot/et format)",
        required=False,
    )

    # Subparser: rep_add_subject
    parser_add_subject = subparsers.add_parser(
        "rep_add_subject", help="Add a new subject"
    )
    parser_add_subject.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_add_subject.add_argument("username", type=str, help="Username")
    parser_add_subject.add_argument("name", type=str, help="Name of the subject")
    parser_add_subject.add_argument("email", type=str, help="Email of the subject")
    parser_add_subject.add_argument(
        "credential_file", type=str, help="Path to the credential file"
    )

    # Subparser: rep_suspend_subject
    parser_suspend_subject = subparsers.add_parser(
        "rep_suspend_subject", help="Suspend a subject"
    )
    parser_suspend_subject.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_suspend_subject.add_argument(
        "username", type=str, help="Username of the subject to suspend"
    )

    # Subparser: rep_activate_subject
    parser_activate_subject = subparsers.add_parser(
        "rep_activate_subject", help="Activate a subject"
    )
    parser_activate_subject.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_activate_subject.add_argument(
        "username", type=str, help="Username of the subject to activate"
    )

    # Subparser: rep_add_role
    parser_add_role = subparsers.add_parser(
        "rep_add_role", help="Add a new role to the organization"
    )
    parser_add_role.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_add_role.add_argument("role", type=str, help="Role name")

    # Subparser: rep_suspend_role
    parser_suspend_role = subparsers.add_parser(
        "rep_suspend_role", help="Suspend a role"
    )
    parser_suspend_role.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_suspend_role.add_argument("role", type=str, help="Role name")

    # Subparser: rep_reactivate_role
    parser_reactivate_role = subparsers.add_parser(
        "rep_reactivate_role", help="Reactivate a role"
    )
    parser_reactivate_role.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_reactivate_role.add_argument("role", type=str, help="Role name")

    # Subparser: rep_add_permission
    parser_add_permission = subparsers.add_parser(
        "rep_add_permission", help="Add a new permission to the organization"
    )
    parser_add_permission.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_add_permission.add_argument("role", type=str, help="Role that is being modified")
    parser_add_permission.add_argument(
        "username_or_permission", type=str, help="Permission name or username"
    )

    # Subparser: rep_remove_permission
    parser_remove_permission = subparsers.add_parser(
        "rep_remove_permission", help="Remove a permission to the organization"
    )
    parser_remove_permission.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_remove_permission.add_argument(
        "role", type=str, help="Role that is being modified"
    )
    parser_remove_permission.add_argument(
        "username_or_permission", type=str, help="Permission name or username"
    )

    # Subparser: rep_add_doc
    parser_add_doc = subparsers.add_parser("rep_add_doc", help="Add a document")
    parser_add_doc.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_add_doc.add_argument("document_name", type=str, help="Name of the document")
    parser_add_doc.add_argument("file", type=str, help="Path to the document file")

    # Subparser: rep_get_doc_metadata
    parser_get_doc_metadata = subparsers.add_parser(
        "rep_get_doc_metadata", help="Get document metadata"
    )
    parser_get_doc_metadata.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_get_doc_metadata.add_argument(
        "document_name", type=str, help="Name of the document"
    )

    # Subparser: rep_get_doc_file
    parser_get_doc_file = subparsers.add_parser(
        "rep_get_doc_file", help="Get a document file"
    )
    parser_get_doc_file.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_get_doc_file.add_argument(
        "document_name", type=str, help="Name of the document"
    )
    parser_get_doc_file.add_argument(
        "--file", "-f", type=str, help="Optional path to save the file", required=False
    )

    # Subparser: rep_delete_doc
    parser_delete_doc = subparsers.add_parser(
        "rep_delete_doc", help="Delete a document"
    )
    parser_delete_doc.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_delete_doc.add_argument(
        "document_name", type=str, help="Name of the document to delete"
    )

    # Subparser: rep_acl_doc
    parser_acl_doc = subparsers.add_parser(
        "rep_acl_doc", help="Change the ACL of a document"
    )
    parser_acl_doc.add_argument(
        "session_file", type=str, help="Path to the session file"
    )
    parser_acl_doc.add_argument("document_name", type=str, help="Name of the document")
    parser_acl_doc.add_argument("operator", type=str, help="Operator [+/-]")
    parser_acl_doc.add_argument("role", type=str, help="Role name")
    parser_acl_doc.add_argument("permission", type=str, help="Permission name")

    # Parse arguments
    args = parser.parse_args()

    # Match commands to functions
    match args.command:
        case "rep_subject_credentials":
            rep_subject_credentials(args.password, args.credential_file)
        case "rep_decrypt_file":
            rep_decrypt_file(args.encrypted_file_path, args.metadata_path)
        case "rep_list_orgs":
            rep_list_orgs()
        case "rep_create_org":
            rep_create_org(
                args.organization,
                args.username,
                args.name,
                args.email,
                args.pub_key_file,
            )
        case "rep_create_session":
            rep_create_session(
                args.organization,
                args.username,
                args.password,
                args.credential_file,
                args.session_file,
            )
        case "rep_get_file":
            rep_get_file(args.file_handle, file=args.file)
        case "rep_assume_role":
            rep_assume_role(args.session_file, args.role)
        case "rep_drop_role":
            rep_drop_role(args.session_file, args.role)
        case "rep_list_roles":
            rep_list_roles(args.session_file, args.role)
        case "rep_list_subjects":
            rep_list_subjects(args.session_file, username=args.username)
        case "rep_list_role_subjects":
            rep_list_role_subjects(args.session_file, args.role)
        case "rep_list_subject_roles":
            rep_list_subject_roles(args.session_file, args.username)
        case "rep_list_role_permissions":
            rep_list_role_permissions(args.session_file, args.role)
        case "rep_list_permission_roles":
            rep_list_permission_roles(args.session_file, args.permission)
        case "rep_list_docs":
            rep_list_docs(args.session_file, username=args.username, date=args.date)
        case "rep_add_subject":
            rep_add_subject(
                args.session_file,
                args.username,
                args.name,
                args.email,
                args.credential_file,
            )
        case "rep_suspend_subject":
            rep_suspend_subject(args.session_file, args.username)
        case "rep_activate_subject":
            rep_activate_subject(args.session_file, args.username)
        case "rep_add_role":
            rep_add_role(args.session_file, args.role)
        case "rep_suspend_role":
            rep_suspend_role(args.session_file, args.role)
        case "rep_reactivate_role":
            rep_reactivate_role(args.session_file, args.role)
        case "rep_add_permission":
            rep_add_permission(
                args.session_file, args.role, args.username_or_permission
            )
        case "rep_remove_permission":
            rep_remove_permission(
                args.session_file, args.role, args.username_or_permission
            )
        case "rep_add_doc":
            rep_add_doc(args.session_file, args.document_name, args.file)
        case "rep_get_doc_metadata":
            rep_get_doc_metadata(args.session_file, args.document_name)
        case "rep_get_doc_file":
            rep_get_doc_file(args.session_file, args.document_name, file=args.file)
        case "rep_delete_doc":
            rep_delete_doc(args.session_file, args.document_name)
        case "rep_acl_doc":
            rep_acl_doc(
                args.session_file,
                args.document_name,
                args.operator,
                args.role,
                args.permission,
            )
        case _:
            print(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
