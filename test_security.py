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
            db.drop_all()      # Wipe any existing tables
            db.create_all()    # Recreate clean tables for the test
            yield client
            db.session.remove()
            db.drop_all()      # Clean up after test completes

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

    client.post('/login', data={'email': 'owner2@test.com', 'password': 'password123'})
    client.post(f'/documents/{doc_id}/revoke/{viewer_id}')

    client.get('/logout')
    client.post('/login', data={'email': 'viewer2@test.com', 'password': 'password123'})
    assert client.get(f'/documents/{doc_id}/download').status_code == 403

def test_unauthorized_deletion_blocked(client):
    """Verify that non-owners cannot delete documents."""
    with app.app_context():
        owner = User(username="owner3", email="owner3@test.com", role="owner")
        attacker = User(username="attacker", email="attacker@test.com", role="viewer")
        owner.set_password("password123")
        attacker.set_password("password123")
        db.session.add_all([owner, attacker])
        db.session.commit()

        doc = Document(title="File", original_filename="file.pdf", stored_filename="uuid3.pdf", category="HR", owner_id=owner.id)
        db.session.add(doc)
        db.session.commit()
        doc_id = doc.id

    client.post('/login', data={'email': 'attacker@test.com', 'password': 'password123'})
    response = client.post(f'/documents/{doc_id}/delete')
    assert response.status_code == 403

def test_invalid_file_upload_rejected(client):
    """Verify that non-PDF files are rejected."""
    with app.app_context():
        owner = User(username="owner4", email="owner4@test.com", role="owner")
        owner.set_password("password123")
        db.session.add(owner)
        db.session.commit()

    client.post('/login', data={'email': 'owner4@test.com', 'password': 'password123'})
    fake_pdf = (io.BytesIO(b"MALICIOUS_SCRIPT_PAYLOAD"), "fake.pdf")
    res = client.post('/upload', data={'document': fake_pdf, 'title': 'Fake PDF', 'category': 'HR'}, follow_redirects=True)
    assert b"not a valid PDF" in res.data