import pytest
from unittest.mock import patch
from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules import models

@pytest.fixture
def file_with_versions(test_file, create_version):
    """Create a file with multiple versions."""
    version1 = create_version(test_file, rule_id="rule-001", modified="2024-01-01T00:00:00.000Z")
    version2 = create_version(
        test_file, 
        rule_id="rule-001", 
        modified="2024-01-02T00:00:00.000Z",
        action=models.VersionAction.MODIFY
    )
    return test_file, version1, version2


def test_version_delete_removes_orphaned_file(test_file, create_version):
    """Test that deleting the last version referencing a file also deletes the file."""
    version = create_version(test_file, rule_id="rule-orphan")
    file_id = test_file.id
    
    # Verify file exists
    assert models.File.objects.filter(id=file_id).exists()
    
    # Delete the version
    version.delete()
    
    # File should be deleted because no versions reference it
    assert not models.File.objects.filter(id=file_id).exists()


def test_version_delete_keeps_file_with_remaining_versions(file_with_versions):
    """Test that deleting a version doesn't delete the file if other versions still reference it."""
    file, version1, version2 = file_with_versions
    file_id = file.id
    
    # Verify file and both versions exist
    assert models.File.objects.filter(id=file_id).exists()
    assert models.Version.objects.filter(id=version1.id).exists()
    assert models.Version.objects.filter(id=version2.id).exists()
    
    # Delete one version
    version1.delete()
    
    # File should still exist because version2 still references it
    assert models.File.objects.filter(id=file_id).exists()
    assert models.Version.objects.filter(id=version2.id).exists()


def test_version_delete_with_multiple_versions_then_all_deleted(file_with_versions):
    """Test that file is deleted only after all versions are deleted."""
    file, version1, version2 = file_with_versions
    file_id = file.id
    
    # Delete first version - file should still exist
    version1.delete()
    assert models.File.objects.filter(id=file_id).exists()
    
    # Delete second version - file should now be deleted
    version2.delete()
    assert not models.File.objects.filter(id=file_id).exists()


def test_version_delete_with_no_file(create_version):
    """Test that deleting a version with no file doesn't cause errors."""
    version = create_version(file=None, rule_id="rule-no-file")
    
    # This should not raise an exception
    version.delete()


def test_version_delete_signal_calls_file_delete(test_file, create_version):
    """Test that the signal properly calls delete on the file when it's orphaned."""
    version = create_version(test_file, rule_id="rule-signal")
    
    with patch.object(models.File, 'delete') as mock_delete:
        version.delete()
        # File.delete() should be called once because no other versions reference it
        mock_delete.assert_called_once()


def test_version_delete_signal_does_not_call_file_delete_with_remaining_versions(file_with_versions):
    """Test that the signal doesn't call delete on the file when other versions exist."""
    file, version1, version2 = file_with_versions
    
    with patch.object(models.File, 'delete') as mock_delete:
        version1.delete()
        # File.delete() should NOT be called because version2 still references it
        mock_delete.assert_not_called()


def test_multiple_rules_same_file(test_file, create_version):
    """Test that a file can be referenced by versions of different rules."""
    # Create versions for different rules referencing the same file
    version_rule1 = create_version(test_file, rule_id="rule-001")
    version_rule2 = create_version(test_file, rule_id="rule-002")
    
    file_id = test_file.id
    
    # Delete version for rule-001
    version_rule1.delete()
    # File should still exist because rule-002's version references it
    assert models.File.objects.filter(id=file_id).exists()
    
    # Delete version for rule-002
    version_rule2.delete()
    # Now file should be deleted
    assert not models.File.objects.filter(id=file_id).exists()


def test_version_delete_with_cloned_from(test_file, create_version):
    """Test that deleting a version with a cloned_from field works correctly."""
    version = create_version(
        test_file, 
        rule_id="rule-clone", 
        cloned_from="rule-original"
    )
    
    # Delete the version - this should still delete the file if it's the only version referencing it
    version.delete()
    
    # File should be deleted because no versions reference it
    assert not models.File.objects.filter(id=test_file.id).exists()

def test_version_multidelete_removes_file(test_file, create_version):
    """Test that deleting multiple versions at once properly deletes the file if all are orphaned."""
    version1 = create_version(test_file, rule_id="rule-multi-001")
    version2 = create_version(test_file, rule_id="rule-multi-002")
    
    file_id = test_file.id
    
    # Delete both versions at once
    models.Version.objects.filter(id__in=[version1.id, version2.id]).delete()
    
    # File should be deleted because no versions reference it
    assert not models.File.objects.filter(id=file_id).exists()

