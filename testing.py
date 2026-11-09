import io
import pytest
from app import app, db
from models import User, Document, DocumentPermission

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client

# 1. Test Unauthorised Access
def test_unauthorised_access_blocked(client):
    """Verify that User B cannot download User A's document without permission (403 Forbidden)."""
    with app.app_context():
        owner = User(username="owner1", email="owner1@test.com", role="owner")
        viewer = User(username="viewer1", email="viewer1@test.com", role="viewer")
        owner.set_password("password123")
        viewer.set_password("password123")
        db.session.add_all([owner, viewer])
        db.session.commit()

        doc = Document(title="Secret Salary", original_filename="salary.pdf", stored_filename="uuid1.pdf", category="HR", owner_id=owner.id)
        db.session.add(doc)
        db.session.commit()
        doc_id = doc.id

    client.post('/login', data={'email': 'viewer1@test.com', 'password': 'password123'})
    response = client.get(f'/documents/{doc_id}/download')
    assert response.status_code == 403

# 2. Test Revoked Access
def test_revoked_access_blocks_immediately(client):
    """Verify that revoking access immediately blocks subsequent download requests."""
    with app.app_context():
        owner = User(username="owner2", email="owner2@test.com", role="owner")
        viewer = User(username="viewer2", email="viewer2@test.com", role="viewer")
        owner.set_password("password123")
        viewer.set_password("password123")
        db.session.add_all([owner, viewer])
        db.session.commit()

        doc = Document(title="Legal Contract", original_filename="contract.pdf", stored_filename="uuid2.pdf", category="Legal", owner_id=owner.id)
        db.session.add(doc)
        db.session.commit()

        perm = DocumentPermission(document_id=doc.id, user_id=viewer.id, permission="read", granted_by=owner.id)
        db.session.add(perm)
        db.session.commit()
        doc_id, viewer_id = doc.id, viewer.id

    # Owner revokes access
    client.post('/login', data={'email': 'owner2@test.com', 'password': 'password123'})
    client.post(f'/documents/{doc_id}/revoke/{viewer_id}')

    # Viewer attempts download -> expects 403
    client.get('/logout')
    client.post('/login', data={'email': 'viewer2@test.com', 'password': 'password123'})
    assert client.get(f'/documents/{doc_id}/download').status_code == 403

# 3. Test Document Editing Permission Verification
def test_document_editing_permissions(client):
    """Verify read vs edit permissions enforcement."""
    with app.app_context():
        owner = User(username="owner3", email="owner3@test.com", role="owner")
        read_viewer = User(username="read_viewer", email="read@test.com", role="viewer")
        edit_viewer = User(username="edit_viewer", email="edit@test.com", role="viewer")
        owner.set_password("password123")
        read_viewer.set_password("password123")
        edit_viewer.set_password("password123")
        db.session.add_all([owner, read_viewer, edit_viewer])
        db.session.commit()

        doc = Document(title="Project Roadmap", original_filename="roadmap.pdf", stored_filename="uuid3.pdf", category="Projects", owner_id=owner.id)
        db.session.add(doc)
        db.session.commit()

        p_read = DocumentPermission(document_id=doc.id, user_id=read_viewer.id, permission="read", granted_by=owner.id)
        p_edit = DocumentPermission(document_id=doc.id, user_id=edit_viewer.id, permission="edit", granted_by=owner.id)
        db.session.add_all([p_read, p_edit])
        db.session.commit()
        doc_id = doc.id

    # Non-owner cannot share or alter permissions
    client.post('/login', data={'email': 'read@test.com', 'password': 'password123'})
    res = client.post(f'/documents/{doc_id}/share', data={'email': 'edit@test.com', 'permission': 'read'})
    assert res.status_code == 403

# 4. Test Invalid Uploads (Magic Byte Validation)
def test_invalid_file_upload_rejected(client):
    """Verify that non-PDF files (e.g. text files renamed as .pdf) are rejected."""
    with app.app_context():
        owner = User(username="owner4", email="owner4@test.com", role="owner")
        owner.set_password("password123")
        db.session.add(owner)
        db.session.commit()

    client.post('/login', data={'email': 'owner4@test.com', 'password': 'password123'})
    fake_pdf = (io.BytesIO(b"MALICIOUS_SCRIPT_PAYLOAD"), "fake.pdf")
    res = client.post('/upload', data={'document': fake_pdf, 'title': 'Fake PDF', 'category': 'HR'}, follow_redirects=True)
    assert b"not a valid PDF" in res.data