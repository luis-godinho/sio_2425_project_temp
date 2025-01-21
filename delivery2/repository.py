import base64
import json
from getpass import getpass
from urllib.parse import unquote

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from flask import Flask, jsonify, request

from .classes import *
from .cryptographer import (
    decrypt,
    decrypt_json,
    encrypt,
    encrypt_json,
)
from .database import db

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

try:
    with open("./delivery2/RepoKeys/Repo.pem", "rb") as f:
        while (password := getpass("Repository private key password: ")) == "":
            continue
        try:
            PRIVATE_KEY = load_pem_private_key(
                f.read(), password=password.encode(), backend=default_backend()
            )
        except:
            print("Wrong credentials. Exiting Repository.")
            exit(-1)
except:
    print("Error: Create the public/private key for the Repository before starting")
    exit(-1)

db.init_app(app)
with app.app_context():
    db.create_all()


@app.route("/organization/create", methods=["POST"])
def create_organization():
    session = db.session()

    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    org_name = data.get("organization")
    username = data.get("username")
    full_name = data.get("name")
    email = data.get("email")
    public_key = data.get("public_key")

    MANAGER_PERMISSIONS = [
        "ROLE_ACL",
        "SUBJECT_NEW",
        "SUBJECT_DOWN",
        "SUBJECT_UP",
        "DOC_NEW",
        "ROLE_NEW",
        "ROLE_DOWN",
        "ROLE_UP",
        "ROLE_MOD",
    ]

    try:
        subject = Subject.query.filter_by(username=username).first()
        if not subject:
            subject = Subject(
                username=username,
                full_name=full_name,
                email=email,
                public_key=public_key,
            )
            session.add(subject)
            session.flush()
            print(f"New subject '{username}' added successfully.")

        new_org = Organization(name=org_name, manager_id=subject.subject_id)
        session.add(new_org)
        session.flush()

        manager_role = Role(org_id=new_org.org_id, name="Manager", is_suspended=False)
        session.add(manager_role)
        session.flush()

        subject_role = SubjectRole(
            subject_id=subject.subject_id, role_id=manager_role.role_id
        )
        session.add(subject_role)
        session.flush()

        for permission in MANAGER_PERMISSIONS:
            org_acl = OrganizationACL(
                org_id=new_org.org_id,
                role_id=manager_role.role_id,
                permission=permission,
            )
            session.add(org_acl)

        org_subject_status = SubjectStatus(
            subject_id=subject.subject_id, org_id=new_org.org_id
        )
        session.add(org_subject_status)

        session.commit()
        print(f"New organization '{org_name}' created with manager role.")

        return jsonify(
            {"success": f"New organization '{org_name}' added successfully."}, 200
        )

    except Exception as e:
        session.rollback()
        print(f"An error occurred: {e}")
        return jsonify(
            {"error": "An error occurred while creating the organization."}, 400
        )

    finally:
        session.close()


@app.route("/organization/list", methods=["GET"])
def org_list():
    orgs = Organization.query.all()
    orgs_list = [
        {"org_id": org.org_id, "org_name": org.name, "manager_id": org.manager_id}
        for org in orgs
    ]
    return jsonify(orgs_list, 200)


@app.route("/session/create", methods=["POST"])
def create_session():
    data_encrypted = json.loads(request.get_json())

    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    organization_name = data.get("organization")
    username = data.get("username")
    rsa_public_key = data.get("rsa_public_key")
    dh_parameters = data.get("dh_parameters")

    subject = Subject.query.filter_by(username=username).first()

    if subject is None:
        return jsonify({"error": "Subject does not exist"}, 400)

    org = Organization.query.filter_by(name=organization_name).first()

    if org is None:
        return jsonify({"error": "Organization does not exist"}, 400)

    parameters = dh.DHParameterNumbers(
        dh_parameters["p"], dh_parameters["g"]
    ).parameters()

    server_private_key = parameters.generate_private_key()
    peer_public_key = dh.DHPublicNumbers(
        dh_parameters["y"], parameters.parameter_numbers()
    ).public_key()

    shared_secret = server_private_key.exchange(peer_public_key)

    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"diffie-hellman-key-exchange",
    ).derive(shared_secret)

    session = Session()
    session.subject_id = subject.subject_id
    session.org_id = org.org_id
    session.keys = rsa_public_key
    session.password = base64.b64encode(symmetric_key).decode()  # Shared Secret

    db_session = db.session()

    db_session.add(session)
    try:
        db.session.commit()
        print(f"New Session '{session.session_id}' added successfully.")
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred: {e}")
        return jsonify({"error": "Could not create the session"}, 400)

    message = encrypt_json(
        {
            "session_id": session.session_id,
            "subject_id": session.subject_id,
            "org_id": session.org_id,
            "y": server_private_key.public_key()
            .public_numbers()
            .y,  # info about server dh_public_key
            "created_at": session.created_at.isoformat(),
        },
        session.keys,
    )

    # print(
    #     f"shared_secret: {base64.b64encode(shared_secret).decode()}; symmetric_key: {base64.b64encode(symmetric_key).decode()}"
    # )

    return jsonify(
        message,
        200,
    )


@app.route("/file/download/<file_handle>", methods=["GET"])
def download_file(file_handle):
    if not file_handle:
        return jsonify({"error": "file handle is required"}, 400)

    file = File.query.filter_by(file_handle=file_handle).first()

    encrypted_data = ""
    if isinstance(file, File):
        encrypted_data = file.content
    else:
        return jsonify({"error": "Wrong type of data"}, 500)

    message = base64.b64encode(encrypted_data).decode()
    return jsonify(message, 200)


@app.route("/role/assume", methods=["POST"])
def assume_role():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = data.get("role")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    role = Role.query.filter_by(org_id=session.org_id, name=role_name).first()

    if role is None:
        message = encrypt_json(
            {"error": "Role does not exist in the organization"}, public_key
        )
        return jsonify(message, 404)

    subject_role = SubjectRole.query.filter_by(
        subject_id=session.subject_id, role_id=role.role_id
    ).first()

    if subject_role is None:
        message = encrypt_json(
            {"error": "Subject does not have the specified role in the organization"},
            public_key,
        )
        return jsonify(
            message,
            403,
        )

    session.role_id = role.role_id

    db_session = db.session

    try:
        db_session.commit()
        print("Session role updated successfully.")
    except Exception as e:
        db_session.rollback()
        print(f"An error occurred: {e}")
        message = encrypt_json(
            {"error": "Could not update the session role"}, public_key
        )
        return jsonify(message, 500)

    message = encrypt_json(
        {"success": f"Session role updated to '{role_name}' successfully"}, public_key
    )
    return jsonify(message, 200)


@app.route("/role/drop", methods=["POST"])
def drop_role():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = data.get("role")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    current_role = Role.query.filter_by(
        role_id=session.role_id, org_id=session.org_id
    ).first()

    if current_role is None or current_role.name != role_name:
        message = encrypt_json(
            {"error": "Role does not match the session's current role"}, session.keys
        )
        return jsonify(message, 400)

    session.role_id = None

    db_session = db.session

    try:
        db_session.commit()
        print("Role removed from session successfully.")
    except Exception as e:
        db_session.rollback()
        print(f"An error occurred: {e}")
        message = encrypt_json(
            {"error": "Could not remove role from the session"}, session.keys
        )
        return jsonify(message, 500)

    message = encrypt_json(
        {"success": f"Role '{role_name}' removed from the session successfully"},
        session.keys,
    )
    return jsonify(message, 200)


@app.route("/roles", methods=["GET"])
def list_roles():
    data = request.args

    session_info = decrypt_json([unquote(data.get("session"))], PRIVATE_KEY)
    session_id = session_info.get("id")
    password = session_info.get("password")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}), 400

    session = Session.query.filter_by(session_id=session_id).first()
    if session is None:
        return jsonify({"error": "Session does not exist"}), 404

    roles = session.organization.roles
    public_key = session.keys

    if roles:
        roles_list = [
            {
                "role_id": role.role_id,
                "role_name": role.name,
                "is_suspended": role.is_suspended,
            }
            for role in roles
        ]
        message = encrypt_json(roles_list, public_key)
        return jsonify(message, 200)
    else:
        public_key = session.keys
        message = encrypt_json({"message": "This session has no roles"}, public_key)
        return jsonify(message, 404)


@app.route("/subject/list", methods=["GET"])
def list_subjects():
    data_encrypted = request.args

    session_info = decrypt_json([unquote(data_encrypted.get("session"))], PRIVATE_KEY)
    session_id = session_info.get("id")
    password = session_info.get("password")
    username_encrypted = (
        unquote(data_encrypted.get("username"))
        if data_encrypted.get("username")
        else None
    )

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    if session is None:
        return jsonify({"error": "Session is not valid"}, 400)

    org_id = session.org_id
    query = (
        db.session.query(Subject)
        .join(SubjectStatus)
        .filter(SubjectStatus.org_id == org_id)
    )

    if username_encrypted:
        username = decrypt_json([username_encrypted], PRIVATE_KEY)
        query = query.filter(Subject.username == username)

    subjects = query.all()

    if subjects:
        subject_list = [
            {
                "subject_id": subject.subject_id,
                "username": subject.username,
                "full_name": subject.full_name,
                "email": subject.email,
                "status": [item.status for item in subject.subject_status][0],
            }
            for subject in subjects
        ]
        public_key = session.keys
        message = encrypt_json(subject_list, public_key)
        return jsonify(message, 200)
    else:
        public_key = session.keys
        message = encrypt_json(
            {"message": "No subjects found for this organization"}, public_key
        )
        return jsonify(message, 400)


@app.route("/role/subject", methods=["GET"])
def list_role_subjects():
    data = request.args
    session_info = decrypt_json([unquote(data.get("session"))], PRIVATE_KEY)
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = decrypt_json([unquote(data.get("role"))], PRIVATE_KEY)

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    role = (
        db.session.query(Role).filter_by(name=role_name, org_id=session.org_id).first()
    )

    if role:
        subjects = role.subjects
        subjects_list = [subject.username for subject in subjects]
        message = encrypt_json(subjects_list, public_key)
        return jsonify(message, 200)
    else:
        message = encrypt_json({"message": "This session has no roles"}, public_key)
        return jsonify(message, 404)


@app.route("/subject/role", methods=["GET"])
def list_subject_roles():
    data = request.args
    session_info = decrypt_json([unquote(data.get("session"))], PRIVATE_KEY)
    session_id = session_info.get("id")
    password = session_info.get("password")
    subject_name = decrypt_json([unquote(data.get("subject"))], PRIVATE_KEY)

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    subject = (
        db.session.query(Subject)
        .join(SubjectStatus.subject)
        .filter(SubjectStatus.org_id == session.org_id)
        .filter(Subject.username == subject_name)
        .first()
    )

    if subject:
        roles = subject.roles
        roles_list = [
            {
                "role_id": role.role_id,
                "role_name": role.name,
                "is_suspended": role.is_suspended,
            }
            for role in roles
        ]

        message = encrypt_json(roles_list, public_key)
        return jsonify(message, 200)
    else:
        message = encrypt_json({"message": "This session has no roles"}, public_key)
        return jsonify(message, 404)


@app.route("/role/permission", methods=["GET"])
def list_role_permissions():
    data = request.args

    session_info = decrypt_json([unquote(data.get("session"))], PRIVATE_KEY)
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = decrypt_json([unquote(data.get("role"))], PRIVATE_KEY)

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    role = Role.query.filter_by(name=role_name, org_id=session.org_id).first()

    if role is None:
        message = encrypt_json(
            {"error": f"Role '{role_name}' does not exist in the organization"},
            public_key,
        )
        return jsonify(message, 404)

    permissions = OrganizationACL.query.filter_by(
        role_id=role.role_id, org_id=session.org_id
    ).all()

    if not permissions:
        message = encrypt_json(
            {"error": f"No permissions found for role '{role_name}'"}, public_key
        )
        return jsonify(message, 404)

    permissions_list = [perm.permission for perm in permissions]
    message = encrypt_json({"permissions": permissions_list}, public_key)
    return jsonify(message, 200)


@app.route("/permission/roles", methods=["GET"])
def list_permission_roles():
    data_encrypted = request.args

    try:
        data = decrypt_json([unquote(data_encrypted.get("session"))], PRIVATE_KEY)
        session_id = data["id"]
        password = data["password"]
        permission = decrypt_json(
            [unquote(data_encrypted.get("permission"))], PRIVATE_KEY
        )
    except Exception as e:
        return jsonify({"error": f"Invalid data: {str(e)}"}, 400)

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    org_id = session.org_id
    public_key = session.keys

    document_permissions = {"DOC_ACL", "DOC_READ", "DOC_DELETE"}

    if permission.upper() in document_permissions:
        query = (
            db.session.query(DocumentACL)
            .join(Document)
            .join(Role)
            .filter(Document.org_id == org_id)
            .filter(DocumentACL.permission == permission.upper())
            .all()
        )

        if query:
            roles_by_document = [
                {
                    "document_name": acl.document.name,
                    "role_name": acl.role.name,
                }
                for acl in query
            ]
            message = encrypt_json(roles_by_document, public_key)
            return jsonify(message, 200)
        else:
            message = encrypt_json(
                {"message": "No roles found for this permission"}, public_key
            )
            return jsonify(message, 404)

    query = Role.query.filter_by(org_id=org_id).all()

    if query:
        roles = [
            {"role_name": role.name, "is_suspended": role.is_suspended}
            for role in query
        ]
        message = encrypt_json(roles, public_key)
        return jsonify(message, 200)
    else:
        message = encrypt_json(
            {"message": "No roles found in the organization"}, public_key
        )
        return jsonify(message, 404)


@app.route("/document/list", methods=["GET"])
def list_docs():
    data = request.args

    session_info = decrypt_json([unquote(data.get("session"))], PRIVATE_KEY)
    session_id = session_info["id"]
    password = session_info["password"]
    username = unquote(data.get("username")) if data.get("username") else None
    date = unquote(data.get("date")) if data.get("date") else None

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    if not session:
        return jsonify({"error": "Session not found"}, 404)

    org_id = session.org_id
    query = Document.query.filter_by(org_id=org_id)
    public_key = session.keys

    if username:
        username = decrypt_json([username], PRIVATE_KEY)
        subject = Subject.query.filter_by(username=username).first()
        if subject:
            query = query.filter_by(creator_id=subject.subject_id)
        else:
            message = encrypt_json({"error": "Subject not found"}, public_key)
            return jsonify(message, 404)
    if date:
        date_and_filter = decrypt_json([date], PRIVATE_KEY)
        date_filter = date_and_filter[0].strip()
        date = date_and_filter[1].strip()
        try:
            date = datetime.strptime(date, "%d-%m-%Y")
        except ValueError:
            message = encrypt_json(
                {"error": "Invalid date format. Use DD-MM-YYYY."}, public_key
            )
            return jsonify(message, 400)

        if date_filter == "nt":
            query = query.filter(Document.create_date > date)
        elif date_filter == "ot":
            query = query.filter(Document.create_date < date)
        elif date_filter == "et":
            query = query.filter(Document.create_date == date)

    documents = query.all()

    if documents:
        document_list = [
            {
                "document_id": doc.document_id,
                "name": doc.name,
                "create_date": doc.create_date.strftime("%d-%m-%Y"),
                "creator_id": doc.creator_id,
            }
            for doc in documents
        ]
        message = encrypt_json(document_list, public_key)
        return jsonify(message, 200)
    else:
        message = encrypt_json(
            {"message": "No documents found for this organization"}, public_key
        )
        return jsonify(message, 400)


@app.route("/subject/add", methods=["POST"])
def add_subject():
    data_encrypted = json.loads(request.get_json())

    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    subject_public_key = data.get("public_key")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}), 400

    session = Session.query.filter_by(session_id=session_id).first()
    public_key = session.keys

    if not has_permission(session, "SUBJECT_NEW"):
        message = encrypt_json(
            {"error": "No permission to add new Subjects"}, public_key
        )
        return jsonify(message, 403)

    org_id = session.org_id

    org = Organization.query.filter_by(org_id=org_id).first()

    if org is None:
        message = encrypt_json({"error": "Organization does not exist"}, public_key)
        return jsonify(message, 400)

    subject = Subject.query.filter_by(username=username).first()

    if subject is None:
        subject = Subject()
        subject.username = username
        subject.full_name = name
        subject.email = email
        subject.public_key = subject_public_key

        db.session.add(subject)
        try:
            db.session.commit()
            print(f"New subject '{username}' added successfully.")
        except Exception as e:
            db.session.rollback()
            print(f"An error occurred: {e}")
            message = encrypt_json({"error": "couldn't create the subject"}, public_key)
            return jsonify(message, 400)

    org_subject = SubjectStatus()
    org_subject.org_id = org_id
    org_subject.subject_id = subject.subject_id

    db.session.add(org_subject)

    try:
        db.session.commit()
        print(f"Added subject '{username}' successfully to organization {org.name}.")
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred: {e}")
        message = encrypt_json(
            {"error": "couldn't add to the organization"}, public_key
        )
        return jsonify(message, 400)

    message = encrypt_json(
        {
            "success": f"Added subject '{username}'successfully to organization {org.name}."
        },
        public_key,
    )
    return jsonify(
        message,
        200,
    )


@app.route("/subject/suspend", methods=["POST"])
def suspend_subject():
    data_encrypted = json.loads(request.get_json())

    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    username = data.get("username")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()
    public_key = session.keys

    if not has_permission(session, "SUBJECT_DOWN"):
        message = encrypt_json(
            {"error": "No permission to suspend Subjects"}, public_key
        )
        return jsonify(message, 403)

    org_id = session.session_id

    subject_status = (
        db.session.query(SubjectStatus)
        .join(Subject)
        .filter(SubjectStatus.org_id == org_id)
        .filter(Subject.username == username)
        .first()
    )

    if not subject_status:
        message = encrypt_json(
            {"error": "Subject not found in the organization"}, public_key
        )
        return jsonify(message, 404)

    try:
        db.session.query(SubjectStatus).filter(
            SubjectStatus.subject_id == subject_status.subject_id,
            SubjectStatus.org_id == subject_status.org_id,
        ).update({"status": "suspended"})
        db.session.commit()
        message = encrypt_json(
            {"message": f"Subject {username} suspended successfully."}, public_key
        )
        return jsonify(message, 200)
    except Exception as e:
        db.session.rollback()
        message = encrypt_json({"error": f"An error occurred: {e}"}, public_key)
        return jsonify(message, 500)


@app.route("/subject/activate", methods=["POST"])
def activate_subject():
    data_encrypted = json.loads(request.get_json())

    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    username = data.get("username")

    if not validate_session(session_id, password):
        return jsonify({"error": "session is not valid"}), 400

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    if not has_permission(session, "SUBJECT_UP"):
        message = encrypt_json(
            {"error": "No permission to activate Subjects"}, public_key
        )
        return jsonify(message, 403)

    org_id = session.session_id

    subject_status = (
        db.session.query(SubjectStatus)
        .join(Subject)
        .filter(SubjectStatus.org_id == org_id)
        .filter(Subject.username == username)
        .first()
    )

    if not subject_status:
        message = encrypt_json(
            {"error": "Subject not found in the organization"}, public_key
        )
        return jsonify(message, 404)

    try:
        db.session.query(SubjectStatus).filter(
            SubjectStatus.subject_id == subject_status.subject_id,
            SubjectStatus.org_id == subject_status.org_id,
        ).update({"status": "active"})
        db.session.commit()
        message = encrypt_json(
            {"message": f"Subject {username} activated successfully."}, public_key
        )
        return jsonify(message, 200)
    except Exception as e:
        db.session.rollback()
        message = encrypt_json({"error": f"An error occurred: {e}"}, public_key)
        return jsonify(message, 500)


@app.route("/role/add", methods=["POST"])
def add_role():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    if not has_permission(session, "ROLE_NEW"):
        message = encrypt_json(
            {
                "error": "Current subject's role does not have permission to create a role"
            },
            public_key,
        )
        return jsonify(message, 403)

    new_role = Role(
        org_id=session.org_id,
        name=data.get("role"),
        is_suspended=False,
    )

    db_session = db.session
    db_session.add(new_role)

    try:
        db_session.commit()
        print("Role created successfully.")
    except Exception as e:
        db_session.rollback()
        print(f"An error occurred: {e}")
        message = encrypt_json({"error": "Could not create the role"}, public_key)
        return jsonify(message, 400)

    message = encrypt_json(
        {"success": f"Role '{new_role.name}' was created successfully"}, public_key
    )
    return jsonify(message, 200)


@app.route("/role/suspend", methods=["POST"])
def suspend_role():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)
    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = data.get("role")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    if not has_permission(session, "ROLE_DOWN"):
        message = encrypt_json({"error": "No permission to suspend Role"}, public_key)
        return jsonify(message, 403)

    if role_name == "Manager":
        message = encrypt_json(
            {"error": "Not possible to suspend Manager Role"}, public_key
        )
        return jsonify(message, 400)

    role = Role.query.filter_by(name=role_name, org_id=session.org_id).first()

    if role is None:
        message = encrypt_json({"error": "Role not found"}, public_key)
        return jsonify(message, 404)

    if role.is_suspended:
        message = encrypt_json({"error": "Role already suspended"}, public_key)
        return jsonify(message, 400)

    role.is_suspended = True

    db_session = db.session
    db_session.add(role)

    try:
        db_session.commit()
        print("Role suspended successfully.")
    except Exception as e:
        db_session.rollback()
        print(f"An error occurred: {e}")
        message = encrypt_json({"error": "Could not suspend role"}, session.keys)
        return jsonify(message, 500)

    message = encrypt_json({"success": "Role has been suspended"}, public_key)
    return jsonify(message, 200)


@app.route("/role/activate", methods=["POST"])
def activate_role():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = data.get("role")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    if not has_permission(session, "ROLE_UP"):
        message = encrypt_json({"error": "No permission to suspend Role"}, public_key)
        return jsonify(message, 403)

    role = Role.query.filter_by(name=role_name, org_id=session.org_id).first()

    if role is None:
        message = encrypt_json({"error": "Role not found"}, public_key)
        return jsonify(message, 404)

    if not role.is_suspended:
        message = encrypt_json({"error": "Role already activated"}, public_key)
        return jsonify(message, 400)

    role.is_suspended = False

    db_session = db.session
    db_session.add(role)

    try:
        db_session.commit()
        print("Role activated successfully.")
    except Exception as e:
        db_session.rollback()
        print(f"An error occurred: {e}")
        message = encrypt_json({"error": "Could not activate role"}, session.keys)
        return jsonify(message, 500)

    message = encrypt_json({"success": "Role has been activated"}, public_key)
    return jsonify(message, 200)


@app.route("/permission/add", methods=["POST"])
def add_permission():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = data.get("role")
    perm = data.get("perm")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}), 400

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    if not has_permission(session, "ROLE_MOD"):
        message = encrypt_json(
            {"error": "Subject does not have permission to modify roles"}, public_key
        )
        return jsonify(message, 403)

    role = Role.query.filter_by(org_id=session.org_id, name=role_name).first()

    if role is None:
        message = encrypt_json(
            {"error": "Role does not exist in the organization"}, public_key
        )
        return jsonify(message, 404)

    valid_permissions = [
        "ROLE_ACL",
        "SUBJECT_NEW",
        "SUBJECT_DOWN",
        "SUBJECT_UP",
        "DOC_NEW",
        "ROLE_NEW",
        "ROLE_DOWN",
        "ROLE_UP",
        "ROLE_MOD",
    ]

    if perm.upper() in valid_permissions:
        role_permission = OrganizationACL.query.filter_by(
            role_id=role.role_id, permission=perm, org_id=session.org_id
        ).first()

        if role_permission:
            message = encrypt_json(
                {"error": f"Permission '{perm}' already exists for the role"},
                public_key,
            )
            return jsonify(message, 400)

        new_permission = OrganizationACL(
            role_id=role.role_id, permission=perm.upper(), org_id=session.org_id
        )
        db_session = db.session
        db_session.add(new_permission)

        try:
            db_session.commit()
            print("Permission added successfully.")
        except Exception as e:
            db_session.rollback()
            print(f"An error occurred: {e}")
            message = encrypt_json(
                {"error": "Could not add permission to the role"}, public_key
            )
            return jsonify(message, 500)

        message = encrypt_json(
            {
                "success": f"Permission '{perm}' added to role '{role_name}' successfully"
            },
            public_key,
        )
        return jsonify(message, 200)

    else:
        subject = Subject.query.filter_by(username=perm).first()

        if subject is None:
            message = encrypt_json(
                {"error": f"User '{perm}' does not exist"}, public_key
            )
            return jsonify(message, 404)

        subject_status = SubjectStatus.query.filter_by(
            subject_id=subject.subject_id, org_id=session.org_id
        ).first()

        if subject_status is None:
            message = encrypt_json(
                {"error": f"User '{perm}' is not part of the organization"}, public_key
            )
            return jsonify(message, 403)

        subject_role = SubjectRole.query.filter_by(
            subject_id=subject.subject_id, role_id=role.role_id
        ).first()

        if subject_role:
            message = encrypt_json(
                {"error": f"User '{perm}' already has the role '{role_name}'"},
                public_key,
            )
            return jsonify(message, 400)

        new_subject_role = SubjectRole(
            subject_id=subject.subject_id, role_id=role.role_id
        )
        db_session = db.session
        db_session.add(new_subject_role)

        try:
            db_session.commit()
            print("Role added to user successfully.")
        except Exception as e:
            db_session.rollback()
            print(f"An error occurred: {e}")
            message = encrypt_json(
                {"error": "Could not assign role to the user"}, public_key
            )
            return jsonify(message, 500)

        message = encrypt_json(
            {"success": f"Role '{role_name}' assigned to user '{perm}' successfully"},
            public_key,
        )
        return jsonify(message, 200)


@app.route("/permission/remove", methods=["POST"])
def remove_permission():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    role_name = data.get("role")
    perm = data.get("perm")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    role = Role.query.filter_by(org_id=session.org_id, name=role_name).first()

    if role is None:
        message = encrypt_json(
            {"error": "Role does not exist in the organization"}, session.keys
        )
        return jsonify(message, 404)

    valid_permissions = [
        "ROLE_ACL",
        "SUBJECT_NEW",
        "SUBJECT_DOWN",
        "SUBJECT_UP",
        "DOC_NEW",
        "ROLE_NEW",
        "ROLE_DOWN",
        "ROLE_UP",
        "ROLE_MOD",
    ]

    if perm.upper() in valid_permissions:
        role_permission = OrganizationACL.query.filter_by(
            role_id=role.role_id, permission=perm, org_id=session.org_id
        ).first()

        if not role_permission:
            message = encrypt_json(
                {"error": f"Permission '{perm}' does not exist for the role"},
                session.keys,
            )
            return jsonify(message, 400)

        db_session = db.session
        db_session.delete(role_permission)

        try:
            db_session.commit()
            print("Permission removed successfully.")
        except Exception as e:
            db_session.rollback()
            print(f"An error occurred: {e}")
            message = encrypt_json(
                {"error": "Could not remove permission from the role"}, session.keys
            )
            return jsonify(message, 500)

        message = encrypt_json(
            {
                "success": f"Permission '{perm}' removed from role '{role_name}' successfully"
            },
            session.keys,
        )
        return jsonify(message, 200)

    else:
        subject = Subject.query.filter_by(username=perm).first()

        if subject is None:
            message = encrypt_json(
                {"error": f"User '{perm}' does not exist"}, session.keys
            )
            return jsonify(message, 404)

        subject_status = SubjectStatus.query.filter_by(
            subject_id=subject.subject_id, org_id=session.org_id
        ).first()

        if subject_status is None:
            message = encrypt_json(
                {"error": f"User '{perm}' is not part of the organization"},
                session.keys,
            )
            return jsonify(message, 403)

        subject_role = SubjectRole.query.filter_by(
            subject_id=subject.subject_id, role_id=role.role_id
        ).first()

        if not subject_role:
            message = encrypt_json(
                {"error": f"User '{perm}' does not have the role '{role_name}'"},
                session.keys,
            )
            return jsonify(message, 400)

        db_session = db.session
        db_session.delete(subject_role)

        try:
            db_session.commit()
            print("Role removed from user successfully.")
        except Exception as e:
            db_session.rollback()
            print(f"An error occurred: {e}")
            message = encrypt_json(
                {"error": "Could not remove role from the user"}, session.keys
            )
            return jsonify(message, 500)

        message = encrypt_json(
            {"success": f"Role '{role_name}' removed from user '{perm}' successfully"},
            session.keys,
        )
        return jsonify(message, 200)


@app.route("/document/add", methods=["POST"])
def add_doc():
    data_encrypted = json.loads(request.get_json())

    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    doc_name = data.get("doc_name")
    file = data.get("file").encode("UTF-8")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}), 400

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    if not has_permission(session, "DOC_NEW"):
        message = encrypt_json(
            {"error": "No permission to create new Document"}, public_key
        )
        return jsonify(message, 403)

    try:
        encrypted_data = encrypt(file)
    except Exception as e:
        message = encrypt_json(
            {"error": "Failed to encrypt file data", "details": str(e)}, public_key
        )
        return jsonify(message, 400)

    document = Document(
        org_id=session.org_id,
        document_handle=doc_name,
        name=doc_name,
        creator_id=session.subject_id,
        file_handle=encrypted_data["file_handle"],
    )

    file = File(
        file_handle=encrypted_data["file_handle"],
        content=encrypted_data["encrypted_data"],
    )

    db_session = db.session
    db_session.add(document)
    db_session.add(file)

    db_session.flush()

    metadata = DocumentMetadata(
        document_id=document.document_id,
        alg=encrypted_data["alg"],
        key=encrypted_data["wrapped_key"],
    )

    db_session.add(metadata)

    acl_permissions = ["DOC_ACL", "DOC_READ", "DOC_DELETE"]
    for permission in acl_permissions:
        document_acl = DocumentACL(
            document_id=document.document_id,
            role_id=session.role_id,
            permission=permission,
        )
        db_session.add(document_acl)

    try:
        db_session.commit()
        print("Document added successfully.")
    except Exception as e:
        db_session.rollback()
        print(f"An error occurred while adding metadata and ACLs: {e}")
        message = encrypt_json({"error": "Could not add metadata or ACLs"}, public_key)
        return jsonify(message, 400)

    message = encrypt_json(
        {"Success": f"Document with name '{doc_name}' was created successfully"},
        public_key,
    )
    return jsonify(message, 200)


@app.route("/document/metadata", methods=["GET"])
def get_metadata():
    data = request.args

    session_info = decrypt_json([unquote(data.get("session"))], PRIVATE_KEY)
    session_id = session_info.get("id")
    password = session_info.get("password")
    doc_name = decrypt_json([unquote(data.get("doc_name"))], PRIVATE_KEY)

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()
    org_id = session.org_id

    public_key = session.keys

    document = Document.query.filter_by(org_id=org_id).filter_by(name=doc_name).first()
    if document is None:
        return jsonify("error", 400)

    if not has_doc_permission(session, document.document_id, "DOC_READ"):
        message = encrypt_json({"error": "No permission to read Document"}, public_key)
        return jsonify(message, 403)

    alg = document.restricted_metadata

    document_alg = [a.alg for a in alg][0]
    document_key = [a.key for a in alg][0]

    message = encrypt_json(
        {
            "document_id": document.document_id,
            "org_id": org_id,
            "document_handle": document.document_handle,
            "name": document.name,
            "create_date": document.create_date.isoformat(),
            "creator_id": document.creator_id,
            "file_handle": document.file_handle,
            "alg": base64.b64encode(document_alg).decode(),
            "wrapped_key": base64.b64encode(document_key).decode(),
        },
        public_key,
    )

    return jsonify(
        message,
        200,
    )


@app.route("/document/getfile", methods=["GET"])
def get_file():
    data = request.args

    session_info = decrypt_json([unquote(data.get("session"))], PRIVATE_KEY)
    session_id = session_info.get("id")
    password = session_info.get("password")
    doc_name = decrypt_json([unquote(data.get("doc_name"))], PRIVATE_KEY)

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys
    org_id = session.org_id

    document = Document.query.filter_by(org_id=org_id).filter_by(name=doc_name).first()
    if document is None:
        message = encrypt_json(
            {"error": f"Document with name {doc_name} does not exist"}, public_key
        )
        return jsonify(message, 400)

    if not has_doc_permission(session, document.document_id, "DOC_READ"):
        message = encrypt_json({"error": "No permission to read Document"}, public_key)
        return jsonify(message, 403)

    file_handle = document.file_handle

    metadata = DocumentMetadata.query.filter_by(
        document_id=document.document_id
    ).first()
    if metadata is None:
        message = encrypt_json({"error": "metadata not found"}, public_key)
        return jsonify(message, 404)

    alg = metadata.alg
    key = metadata.key

    file = File.query.filter_by(file_handle=file_handle).first()
    file_content = decrypt(file.content, key, alg)

    if file is None:
        message = encrypt_json(
            {"error": f"file handle {file_content} not found"}, public_key
        )
        return jsonify(message, 404)

    if file_content == 404:
        message = encrypt_json({"error": "Failed decryption."}, public_key)
        return jsonify(message, 400)

    if file_content == -1:
        message = encrypt_json({"error": "Integrity check failed"}, public_key)
        return jsonify(message, 400)

    message = encrypt_json(file_content.decode("UTF-8"), public_key)

    return jsonify(message, 200)


@app.route("/document/delete", methods=["POST"])
def delete_file():
    data_encrypted = json.loads(request.get_json())

    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    doc_name = data.get("doc_name")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}), 400

    session = Session.query.filter_by(session_id=session_id).first()
    if session is None:
        return jsonify({"error": "Session does not exist"}), 404

    org_id = session.org_id
    subject_id = session.subject_id
    public_key = session.keys

    document = Document.query.filter_by(org_id=org_id, name=doc_name).first()
    if document is None:
        message = encrypt_json(
            {"error": f"Document '{doc_name}' not found in organization {org_id}"},
            public_key,
        )
        return jsonify(message, 404)

    if not has_doc_permission(session, document.document_id, "DOC_DELETE"):
        message = encrypt_json(
            {"error": "No permission to delete Document"}, public_key
        )
        return jsonify(message, 403)

    document.deleter_id = subject_id

    try:
        db.session.commit()
        message = encrypt_json(
            {"message": f"Document '{doc_name}' deleted by subject {subject_id}."},
            public_key,
        )
        return jsonify(message, 200)
    except Exception as e:
        db.session.rollback()
        message = encrypt_json({"error": f"An error occurred: {e}"}, public_key)
        return jsonify(message, 500)


@app.route("/document/acl", methods=["POST"])
def doc_acl():
    data_encrypted = json.loads(request.get_json())
    data = decrypt_json(data_encrypted, PRIVATE_KEY)

    session_info = data.get("session")
    session_id = session_info.get("id")
    password = session_info.get("password")
    doc_name = data.get("doc")
    op = data.get("op")
    role_name = data.get("role")
    perm = data.get("perm")

    if not validate_session(session_id, password):
        return jsonify({"error": "Session is not valid"}, 400)

    session = Session.query.filter_by(session_id=session_id).first()

    public_key = session.keys

    document = Document.query.filter_by(name=doc_name, org_id=session.org_id).first()

    if document is None:
        message = encrypt_json(
            {"error": "Document not found in the organization"}, public_key
        )
        return jsonify(message, 404)

    if not has_doc_permission(session, document.document_id, "DOC_ACL"):
        message = encrypt_json(
            {"error": "No permission to modify Document ACL"}, public_key
        )
        return jsonify(message, 403)

    role = Role.query.filter_by(name=role_name, org_id=session.org_id).first()

    if role is None:
        message = encrypt_json(
            {"error": "Role does not exist in the organization"}, public_key
        )
        return jsonify(message, 404)

    valid_permissions = ["DOC_ACL", "DOC_READ", "DOC_DELETE"]

    if perm.upper() not in valid_permissions:
        message = encrypt_json({"error": f"Invalid permission: {perm}"}, public_key)
        return jsonify(message, 400)

    db_session = db.session

    if op == "+":
        existing_acl = DocumentACL.query.filter_by(
            document_id=document.document_id,
            role_id=role.role_id,
            permission=perm.upper(),
        ).first()

        if existing_acl:
            message = encrypt_json(
                {"error": f"Permission '{perm}' already exists for the role"},
                public_key,
            )
            return jsonify(message, 400)

        new_acl = DocumentACL(
            document_id=document.document_id,
            role_id=role.role_id,
            permission=perm.upper(),
        )
        db_session.add(new_acl)

        try:
            db_session.commit()
            print("Permission added successfully.")
        except Exception as e:
            db_session.rollback()
            print(f"An error occurred: {e}")
            message = encrypt_json(
                {"error": "Could not add permission to the role"}, public_key
            )
            return jsonify(message, 500)

        message = encrypt_json(
            {
                "success": f"Permission '{perm}' added to role '{role_name}' for document '{doc_name}'"
            },
            public_key,
        )
        return jsonify(message, 200)

    elif op == "-":
        existing_acl = DocumentACL.query.filter_by(
            document_id=document.document_id,
            role_id=role.role_id,
            permission=perm.upper(),
        ).first()

        if not existing_acl:
            message = encrypt_json(
                {"error": f"Permission '{perm}' does not exist for the role"},
                public_key,
            )
            return jsonify(message, 400)

        db_session.delete(existing_acl)

        try:
            db_session.commit()
            print("Permission removed successfully.")
        except Exception as e:
            db_session.rollback()
            print(f"An error occurred: {e}")
            message = encrypt_json(
                {"error": "Could not remove permission from the role"}, public_key
            )
            return jsonify(message, 500)

        message = encrypt_json(
            {
                "success": f"Permission '{perm}' removed from role '{role_name}' for document '{doc_name}'"
            },
            public_key,
        )
        return jsonify(message, 200)

    else:
        message = encrypt_json(
            {"error": "Invalid operation. Use '+' to add or '-' to remove permissions"},
            public_key,
        )
        return jsonify(message, 400)


def validate_session(session_id, password, timeout=3600):
    session = Session.query.filter_by(session_id=session_id).first()
    if session is None:
        return False

    if password != decrypt_password(session.password):
        return False

    org = Organization.query.filter_by(org_id=session.org_id).first()
    if org is None:
        return False

    subject = Subject.query.filter_by(subject_id=session.subject_id)
    if subject is None:
        return False

    current_time = datetime.now()
    session_time = session.created_at
    time_difference = current_time - session_time

    if time_difference.total_seconds() > timeout:
        return False

    return True


def has_permission(session, permission_to_check):
    role_id = session.role_id

    if role_id is None:
        return False

    permission_exists = OrganizationACL.query.filter_by(
        role_id=role_id, org_id=session.org_id, permission=permission_to_check
    ).first()

    if permission_exists:
        return True
    else:
        return False


def has_doc_permission(session, doc_id, permission_to_check):
    role_id = session.role_id

    if role_id is None:
        return False

    permission_exists = DocumentACL.query.filter_by(
        role_id=role_id, document_id=doc_id, permission=permission_to_check
    ).first()

    if permission_exists:
        return True
    else:
        return False
