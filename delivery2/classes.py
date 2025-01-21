from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Boolean,
    JSON,
    CheckConstraint,
)
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import db


class Organization(db.Model):
    __tablename__ = "organizations"

    org_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    manager_id = Column(Integer, ForeignKey("subjects.subject_id"), nullable=False)

    creator = relationship("Subject", back_populates="organizations_created")
    roles = relationship("Role", back_populates="organization")
    documents = relationship("Document", back_populates="organization")
    sessions = relationship("Session", back_populates="organization")
    acls = relationship("OrganizationACL", back_populates="organization")


class Subject(db.Model):
    __tablename__ = "subjects"

    subject_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False, unique=True)
    full_name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    public_key = Column(String, nullable=False)

    organizations_created = relationship("Organization", back_populates="creator")
    roles = relationship("Role", secondary="subject_roles", back_populates="subjects")
    sessions = relationship("Session", back_populates="subject")
    subject_status = relationship("SubjectStatus", back_populates="subject")


class Role(db.Model):
    __tablename__ = "roles"

    role_id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    name = Column(String, nullable=False)
    is_suspended = Column(Boolean, default=False)

    organization = relationship("Organization", back_populates="roles")
    subjects = relationship(
        "Subject", secondary="subject_roles", back_populates="roles"
    )
    acls = relationship("DocumentACL", back_populates="role")
    sessions = relationship("Session", back_populates="roles")


class SubjectRole(db.Model):
    __tablename__ = "subject_roles"

    subject_id = Column(Integer, ForeignKey("subjects.subject_id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.role_id"), primary_key=True)

    roles = relationship("Role")
    subjects = relationship("Subject")


class Document(db.Model):
    __tablename__ = "documents"

    document_id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    document_handle = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    create_date = Column(DateTime, default=datetime.now())
    creator_id = Column(Integer, ForeignKey("subjects.subject_id"), nullable=False)
    file_handle = Column(String)
    deleter_id = Column(Integer, ForeignKey("subjects.subject_id"))

    organization = relationship("Organization", back_populates="documents")
    # creator = relationship('Subject', back_populates='documents_created', foreign_keys=[creator_id])
    # deleter = relationship('Subject', back_populates='documents_deleted', foreign_keys=[deleter_id])
    acl = relationship("DocumentACL", back_populates="document")
    restricted_metadata = relationship("DocumentMetadata", back_populates="document")


class DocumentMetadata(db.Model):
    __tablename__ = "document_metadata"

    document_id = Column(Integer, ForeignKey("documents.document_id"), primary_key=True)
    alg = Column(String)
    key = Column(String)

    document = relationship("Document", back_populates="restricted_metadata")


class File(db.Model):
    __tablename__ = "files"

    file_handle = Column(String, primary_key=True)
    content = Column(String, nullable=False)


class Session(db.Model):
    __tablename__ = "sessions"

    session_id = Column(Integer, primary_key=True, autoincrement=True)
    subject_id = Column(Integer, ForeignKey("subjects.subject_id"), nullable=False)
    password = Column(String)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    keys = Column(JSON, nullable=False)  # Store session keys in JSON format
    created_at = Column(DateTime, default=datetime.now())
    role_id = Column(Integer, ForeignKey("roles.role_id"))

    subject = relationship("Subject", back_populates="sessions")
    organization = relationship("Organization", back_populates="sessions")
    roles = relationship("Role", back_populates="sessions")


class SubjectStatus(db.Model):
    __tablename__ = "subject_status"

    status_id = Column(Integer, primary_key=True, autoincrement=True)
    subject_id = Column(Integer, ForeignKey("subjects.subject_id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    status = Column(
        String, CheckConstraint("status IN ('active', 'suspended')"), default="active"
    )

    subject = relationship("Subject", back_populates="subject_status")
    organization = relationship("Organization")


class OrganizationACL(db.Model):
    __tablename__ = "org_acls"

    org_id = Column(Integer, ForeignKey("organizations.org_id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.role_id"), primary_key=True)
    permission = Column(String, nullable=False, primary_key=True)

    organization = relationship("Organization", back_populates="acls")
    role = relationship("Role")


class DocumentACL(db.Model):
    __tablename__ = "document_acls"

    document_id = Column(Integer, ForeignKey("documents.document_id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.role_id"), primary_key=True)
    permission = Column(String, nullable=False, primary_key=True)

    document = relationship("Document", back_populates="acl")
    role = relationship("Role", back_populates="acls")
