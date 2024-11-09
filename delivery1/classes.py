from typing import NamedTuple
from datetime import datetime
import sqlite3

class Organization(NamedTuple):
    organization_id: int
    name: str
    manager_id: int

class Subject(NamedTuple):
    subject_id: int
    username: str
    full_name: str
    email: str
    public_key: str

class Document(NamedTuple):
    document_id: int
    document_handle: int
    name: str
    create_date: datetime 
    creator_id: int
    file_handle: str
    organization_id: int
    deleter_id: int

class file(NamedTuple):
    file_id:int
    file_handle: str
    alg: str
    key: str

class acl(NamedTuple):
    acl_id: int
    document_id: int
    organization_id: int
    subject_id: int
    doc_acl: bool
    doc_read: bool
    doc_delete: bool
    role_acl: bool
    subject_new: bool
    subject_down: bool
    subject_up: bool
    doc_new: bool

def list_all_orgs() -> list[Organization]:
    connection = sqlite3.connect("documents")
    cursor = connection.cursor()

    cursor.execute("select * from organization")

    return list(map(lambda row: Organization(*row), cursor))

def create_org(org_name, manager_id):
    connection = sqlite3.connect("documents")
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO organization (name, manager_id) VALUES (?, ?)",
        (org_name, manager_id)
    )
    
    organization_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return organization_id
