"""
sharing/tests.py

Tests for:
  - GET/POST/DELETE  /api/files/<file_id>/share/                       → file_share_view
  - POST             /api/files/<file_id>/share/collaborators/         → add_collaborator
  - DELETE           /api/files/<file_id>/share/collaborators/<id>/    → remove_collaborator
  - GET              /api/shared/<token>/                              → shared_file_view

Run:
    python manage.py test sharing.tests
"""

import uuid

from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from storage.models import File as FileModel
from sharing.models import FileShare, FileShareCollaborator

User = get_user_model()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_user(username="shareuser", email="share@example.com", password="pass1234!"):
    return User.objects.create_user(username=username, email=email, password=password)


def jwt(user):
    token = RefreshToken.for_user(user)
    return {"HTTP_AUTHORIZATION": f"Bearer {token.access_token}"}


def make_file_record(user, name="shareable.txt", size=512):
    obj = FileModel(user=user, name=name, size=size)
    obj.file.name = f"uploads/{name}"
    obj.save()
    return obj


def make_active_share(file_obj, owner, permission="read"):
    return FileShare.objects.create(
        file=file_obj,
        owner=owner,
        is_active=True,
        link_permission=permission,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Share — GET
# ─────────────────────────────────────────────────────────────────────────────

class GetShareTests(APITestCase):
    """GET /api/files/<file_id>/share/"""

    def setUp(self):
        self.user = make_user()
        self.file = make_file_record(self.user)
        self.url = reverse("file-share", kwargs={"file_id": self.file.id})

    def test_returns_404_when_no_share_exists(self):
        resp = self.client.get(self.url, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_returns_200_with_existing_active_share(self):
        make_active_share(self.file, self.user)
        resp = self.client.get(self.url, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_response_contains_token_and_permission(self):
        make_active_share(self.file, self.user, permission="read_upload")
        resp = self.client.get(self.url, **jwt(self.user))
        self.assertIn("token", resp.data)
        self.assertEqual(resp.data["link_permission"], "read_upload")

    def test_requires_authentication(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_cannot_view_another_users_share(self):
        other = make_user("spy", "spy@example.com")
        resp = self.client.get(self.url, **jwt(other))
        # 404 because the file doesn't belong to other
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_revoked_share_still_returned_by_owner(self):
        """Owner can see a revoked share so they know it exists."""
        share = make_active_share(self.file, self.user)
        share.is_active = False
        share.save()
        resp = self.client.get(self.url, **jwt(self.user))
        # The view currently returns the first() match regardless of is_active
        self.assertEqual(resp.status_code, status.HTTP_200_OK)


# ─────────────────────────────────────────────────────────────────────────────
# Share — POST (create / update)
# ─────────────────────────────────────────────────────────────────────────────

class CreateUpdateShareTests(APITestCase):
    """POST /api/files/<file_id>/share/"""

    def setUp(self):
        self.user = make_user()
        self.file = make_file_record(self.user)
        self.url = reverse("file-share", kwargs={"file_id": self.file.id})

    # ── Create ───────────────────────────────────────────────────────────────

    def test_create_share_returns_201(self):
        resp = self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_create_share_persists_to_db(self):
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        self.assertTrue(FileShare.objects.filter(file=self.file, owner=self.user).exists())

    def test_create_share_is_active_by_default(self):
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        share = FileShare.objects.get(file=self.file, owner=self.user)
        self.assertTrue(share.is_active)

    def test_create_share_default_permission_read(self):
        self.client.post(self.url, {}, **jwt(self.user))
        share = FileShare.objects.get(file=self.file, owner=self.user)
        self.assertEqual(share.link_permission, "read")

    def test_create_share_read_upload_permission(self):
        self.client.post(self.url, {"link_permission": "read_upload"}, **jwt(self.user))
        share = FileShare.objects.get(file=self.file, owner=self.user)
        self.assertEqual(share.link_permission, "read_upload")

    def test_create_share_generates_unique_uuid_token(self):
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        share = FileShare.objects.get(file=self.file, owner=self.user)
        self.assertIsNotNone(share.token)
        self.assertEqual(len(str(share.token)), 36)   # standard UUID4 length

    def test_create_share_response_contains_share_url(self):
        resp = self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        self.assertIn("share_url", resp.data)
        share = FileShare.objects.get(file=self.file, owner=self.user)
        self.assertIn(str(share.token), resp.data["share_url"])

    def test_create_share_invalid_permission_returns_400(self):
        resp = self.client.post(self.url, {"link_permission": "write"}, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_share_requires_authentication(self):
        resp = self.client.post(self.url, {"link_permission": "read"})
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_share_for_nonexistent_file_returns_404(self):
        url = reverse("file-share", kwargs={"file_id": 99999})
        resp = self.client.post(url, {"link_permission": "read"}, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    # ── Update (idempotent second POST) ──────────────────────────────────────

    def test_second_post_returns_200_not_201(self):
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        resp = self.client.post(self.url, {"link_permission": "read_upload"}, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_second_post_does_not_create_duplicate(self):
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        self.client.post(self.url, {"link_permission": "read_upload"}, **jwt(self.user))
        self.assertEqual(
            FileShare.objects.filter(file=self.file, owner=self.user).count(), 1
        )

    def test_update_changes_permission(self):
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        self.client.post(self.url, {"link_permission": "read_upload"}, **jwt(self.user))
        share = FileShare.objects.get(file=self.file, owner=self.user)
        self.assertEqual(share.link_permission, "read_upload")

    def test_post_on_revoked_share_reactivates_it(self):
        share = FileShare.objects.create(
            file=self.file, owner=self.user, is_active=False, link_permission="read"
        )
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        share.refresh_from_db()
        self.assertTrue(share.is_active)

    def test_token_unchanged_after_update(self):
        """Updating a share must not regenerate the token."""
        self.client.post(self.url, {"link_permission": "read"}, **jwt(self.user))
        original_token = FileShare.objects.get(file=self.file, owner=self.user).token
        self.client.post(self.url, {"link_permission": "read_upload"}, **jwt(self.user))
        updated_token = FileShare.objects.get(file=self.file, owner=self.user).token
        self.assertEqual(original_token, updated_token)


# ─────────────────────────────────────────────────────────────────────────────
# Share — DELETE (revoke)
# ─────────────────────────────────────────────────────────────────────────────

class RevokeShareTests(APITestCase):
    """DELETE /api/files/<file_id>/share/"""

    def setUp(self):
        self.user = make_user()
        self.file = make_file_record(self.user)
        self.url = reverse("file-share", kwargs={"file_id": self.file.id})

    def test_revoke_sets_is_active_false(self):
        make_active_share(self.file, self.user)
        resp = self.client.delete(self.url, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        share = FileShare.objects.get(file=self.file)
        self.assertFalse(share.is_active)

    def test_revoke_does_not_delete_record(self):
        """Revoking should soft-deactivate, not hard-delete."""
        make_active_share(self.file, self.user)
        self.client.delete(self.url, **jwt(self.user))
        self.assertTrue(FileShare.objects.filter(file=self.file).exists())

    def test_revoke_nonexistent_share_returns_404(self):
        resp = self.client.delete(self.url, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_revoke_other_users_share_returns_404(self):
        other = make_user("other_r", "other_r@example.com")
        make_active_share(self.file, self.user)
        resp = self.client.delete(self.url, **jwt(other))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_revoke_requires_authentication(self):
        make_active_share(self.file, self.user)
        resp = self.client.delete(self.url)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)


# ─────────────────────────────────────────────────────────────────────────────
# Collaborators — Add
# ─────────────────────────────────────────────────────────────────────────────

class AddCollaboratorTests(APITestCase):
    """POST /api/files/<file_id>/share/collaborators/"""

    def setUp(self):
        self.user = make_user()
        self.file = make_file_record(self.user)
        self.share = make_active_share(self.file, self.user)
        self.url = reverse("file-share-add-collab", kwargs={"file_id": self.file.id})

    # ── Success ──────────────────────────────────────────────────────────────

    def test_add_collaborator_returns_201(self):
        resp = self.client.post(
            self.url, {"email": "alice@example.com", "permission": "read"}, **jwt(self.user)
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_add_collaborator_persists_to_db(self):
        self.client.post(
            self.url, {"email": "alice@example.com", "permission": "read"}, **jwt(self.user)
        )
        self.assertTrue(
            FileShareCollaborator.objects.filter(share=self.share, email="alice@example.com").exists()
        )

    def test_add_collaborator_read_upload_permission(self):
        self.client.post(
            self.url, {"email": "bob@example.com", "permission": "read_upload"}, **jwt(self.user)
        )
        collab = FileShareCollaborator.objects.get(share=self.share, email="bob@example.com")
        self.assertEqual(collab.permission, "read_upload")

    def test_add_collaborator_email_stored_lowercase(self):
        """Mixed-case email input must be normalised to lowercase."""
        self.client.post(
            self.url, {"email": "Carol@Example.COM", "permission": "read"}, **jwt(self.user)
        )
        self.assertTrue(
            FileShareCollaborator.objects.filter(email="carol@example.com").exists()
        )
        self.assertFalse(
            FileShareCollaborator.objects.filter(email="Carol@Example.COM").exists()
        )

    def test_add_duplicate_email_updates_permission(self):
        """Re-posting same email should update permission, not create duplicate row."""
        self.client.post(self.url, {"email": "dave@example.com", "permission": "read"}, **jwt(self.user))
        resp = self.client.post(self.url, {"email": "dave@example.com", "permission": "read_upload"}, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(
            FileShareCollaborator.objects.filter(share=self.share, email="dave@example.com").count(), 1
        )
        collab = FileShareCollaborator.objects.get(share=self.share, email="dave@example.com")
        self.assertEqual(collab.permission, "read_upload")

    def test_response_contains_collaborator_fields(self):
        resp = self.client.post(
            self.url, {"email": "eve@example.com", "permission": "read"}, **jwt(self.user)
        )
        for key in ("id", "email", "permission"):
            self.assertIn(key, resp.data)

    # ── Validation ───────────────────────────────────────────────────────────

    def test_missing_email_returns_400(self):
        resp = self.client.post(self.url, {"permission": "read"}, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_email_format_returns_400(self):
        resp = self.client.post(
            self.url, {"email": "not-an-email", "permission": "read"}, **jwt(self.user)
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_permission_returns_400(self):
        resp = self.client.post(
            self.url, {"email": "frank@example.com", "permission": "admin"}, **jwt(self.user)
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_empty_email_string_returns_400(self):
        resp = self.client.post(
            self.url, {"email": "   ", "permission": "read"}, **jwt(self.user)
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    # ── Auth / ownership ─────────────────────────────────────────────────────

    def test_requires_authentication(self):
        resp = self.client.post(self.url, {"email": "g@example.com", "permission": "read"})
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_other_user_cannot_add_collaborator(self):
        other = make_user("other_c", "other_c@example.com")
        resp = self.client.post(
            self.url, {"email": "h@example.com", "permission": "read"}, **jwt(other)
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_no_share_returns_404(self):
        new_file = make_file_record(self.user, "noshare.txt")
        url = reverse("file-share-add-collab", kwargs={"file_id": new_file.id})
        resp = self.client.post(url, {"email": "i@example.com", "permission": "read"}, **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)


# ─────────────────────────────────────────────────────────────────────────────
# Collaborators — Remove
# ─────────────────────────────────────────────────────────────────────────────

class RemoveCollaboratorTests(APITestCase):
    """DELETE /api/files/<file_id>/share/collaborators/<collab_id>/"""

    def setUp(self):
        self.user = make_user()
        self.file = make_file_record(self.user)
        self.share = make_active_share(self.file, self.user)
        self.collab = FileShareCollaborator.objects.create(
            share=self.share, email="collab@example.com", permission="read"
        )

    def _url(self, collab_id):
        return reverse(
            "file-share-remove-collab",
            kwargs={"file_id": self.file.id, "collab_id": collab_id},
        )

    def test_remove_returns_204(self):
        resp = self.client.delete(self._url(self.collab.id), **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_deletes_db_record(self):
        self.client.delete(self._url(self.collab.id), **jwt(self.user))
        self.assertFalse(FileShareCollaborator.objects.filter(id=self.collab.id).exists())

    def test_remove_nonexistent_collaborator_returns_404(self):
        resp = self.client.delete(self._url(99999), **jwt(self.user))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_other_user_cannot_remove_collaborator(self):
        other = make_user("other_rm", "other_rm@example.com")
        resp = self.client.delete(self._url(self.collab.id), **jwt(other))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_requires_authentication(self):
        resp = self.client.delete(self._url(self.collab.id))
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_share_unaffected_after_collab_removed(self):
        """Removing a collaborator must not affect the share record itself."""
        self.client.delete(self._url(self.collab.id), **jwt(self.user))
        self.share.refresh_from_db()
        self.assertTrue(self.share.is_active)


# ─────────────────────────────────────────────────────────────────────────────
# Public token access — shared_file_view
# ─────────────────────────────────────────────────────────────────────────────

class SharedFileViewTests(APITestCase):
    """GET /api/shared/<token>/"""

    def setUp(self):
        self.owner = make_user("owner", "owner@example.com")
        self.file = make_file_record(self.owner)
        self.share = make_active_share(self.file, self.owner, permission="read")
        self.url = reverse("shared-file", kwargs={"token": self.share.token})

    def _add_collab(self, email, permission="read"):
        return FileShareCollaborator.objects.create(
            share=self.share, email=email, permission=permission
        )

    # ── Open link (no collaborators) ─────────────────────────────────────────

    def test_open_link_accessible_anonymously(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_open_link_response_shape(self):
        resp = self.client.get(self.url)
        for key in ("file_id", "file_name", "file_url", "file_size", "permission"):
            self.assertIn(key, resp.data, msg=f"Missing key: {key}")

    def test_open_link_returns_correct_file_id(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.data["file_id"], self.file.id)

    def test_open_link_returns_correct_file_name(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.data["file_name"], self.file.name)

    def test_open_link_returns_correct_permission_read(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.data["permission"], "read")

    def test_open_link_returns_correct_permission_read_upload(self):
        self.share.link_permission = "read_upload"
        self.share.save()
        resp = self.client.get(self.url)
        self.assertEqual(resp.data["permission"], "read_upload")

    # ── Inactive / bad token ─────────────────────────────────────────────────

    def test_revoked_link_returns_404(self):
        self.share.is_active = False
        self.share.save()
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_invalid_token_returns_404(self):
        url = reverse("shared-file", kwargs={"token": uuid.uuid4()})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_reactivated_link_is_accessible_again(self):
        self.share.is_active = False
        self.share.save()
        self.share.is_active = True
        self.share.save()
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    # ── Collaborator-restricted link ─────────────────────────────────────────

    def test_collab_link_denies_anonymous(self):
        self._add_collab("allowed@example.com")
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_collab_link_allows_listed_user(self):
        allowed = make_user("allowed", "allowed@example.com")
        self._add_collab("allowed@example.com")
        resp = self.client.get(self.url, **jwt(allowed))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_collab_link_denies_unlisted_user(self):
        stranger = make_user("stranger", "stranger@example.com")
        self._add_collab("someone_else@example.com")
        resp = self.client.get(self.url, **jwt(stranger))
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_collab_link_denies_owner_not_in_list(self):
        """Owner accessing via a collaborator-restricted token they're not listed on."""
        self._add_collab("notowner@example.com")
        resp = self.client.get(self.url, **jwt(self.owner))
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_collab_link_allows_owner_when_in_list(self):
        self._add_collab("owner@example.com")
        resp = self.client.get(self.url, **jwt(self.owner))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_collab_link_email_check_is_case_insensitive(self):
        """User with mixed-case email should still pass the collaborator check."""
        user = make_user("mixedcase", "MixedCase@Example.com")
        self._add_collab("mixedcase@example.com")   # stored lowercase
        resp = self.client.get(self.url, **jwt(user))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_removing_all_collabs_reopens_link_publicly(self):
        collab = self._add_collab("temp@example.com")
        collab.delete()
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_multiple_collaborators_each_allowed(self):
        user_a = make_user("ua", "ua@example.com")
        user_b = make_user("ub", "ub@example.com")
        self._add_collab("ua@example.com")
        self._add_collab("ub@example.com")
        for u in (user_a, user_b):
            resp = self.client.get(self.url, **jwt(u))
            self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_collab_read_upload_permission_returned(self):
        allowed = make_user("rw", "rw@example.com")
        self._add_collab("rw@example.com", permission="read_upload")
        # share-level permission is what the endpoint returns
        resp = self.client.get(self.url, **jwt(allowed))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("permission", resp.data)