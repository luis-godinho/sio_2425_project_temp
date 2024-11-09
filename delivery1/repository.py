from delivery1.classes import create_org, list_all_orgs, create_subject
from flask import Flask, request
import json

app = Flask(__name__)

organizations = {}

@app.route("/organization/list")
def org_list():
    return json.dumps(list_all_orgs())

@app.route("/organization/create", method=["POST"])
def create_organization():
    data = request.json

    org_name = data.get("organization")
    username = data.get("username")
    full_name = data.get("name")
    email = data.get("email")
    public_key = data.get("public_key")

    id = create_subject(username, full_name, email, public_key)

    create_org(org_name, id)


