from delivery1.classes import create_org, list_all_orgs
from flask import Flask
import json

app = Flask(__name__)

organizations = {}

@app.route("/organization/list")
def org_list():
    return json.dumps(list_all_orgs())

@app.route("/organization/create/<org_name>", method=["POST"])
def create_organization(org_name):
    create_org(org_name, 0)
