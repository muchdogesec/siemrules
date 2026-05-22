
import pytest

from unittest.mock import patch
from siemrules.siemrules import models
from rest_framework import status


class TestRuleDelete:
    @pytest.fixture
    def mock_delete_rule(self):
        with patch('siemrules.siemrules.arangodb_helpers.delete_rule') as mock_delete_rule:
            yield mock_delete_rule

    def test_rule_destroy_removes_all_versions_via_api(self, client, test_file, create_version, mock_delete_rule):
        """Test that destroying a rule via API endpoint removes all versions."""
        indicator_id = "indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6"
        
        # Create multiple versions for the same rule
        version1 = create_version(
            test_file, 
            rule_id=indicator_id, 
            modified="2024-01-01T00:00:00.000Z"
        )
        version2 = create_version(
            test_file, 
            rule_id=indicator_id, 
            modified="2024-01-02T00:00:00.000Z",
            action=models.VersionAction.MODIFY
        )
        version3 = create_version(
            test_file, 
            rule_id=indicator_id, 
            modified="2024-01-03T00:00:00.000Z",
            action=models.VersionAction.MODIFY
        )
        
        # Verify all versions exist
        assert models.Version.objects.filter(rule_id=indicator_id).count() == 3
        
        # Delete via API endpoint
        response = client.delete(f"/api/v1/base-rules/{indicator_id}/")
        assert response.status_code == status.HTTP_204_NO_CONTENT
        mock_delete_rule.assert_called_once_with(indicator_id)
        
        # All versions should be deleted
        assert models.Version.objects.filter(rule_id=indicator_id).count() == 0
        assert not models.Version.objects.filter(id=version1.id).exists()
        assert not models.Version.objects.filter(id=version2.id).exists()
        assert not models.Version.objects.filter(id=version3.id).exists()


    def test_rule_destroy_removes_all_versions_and_orphaned_file_via_api(self, client, test_file, create_version, mock_delete_rule):
        """Test that destroying a rule via API removes all versions and the orphaned file."""
        indicator_id = "indicator--4fa85f64-5717-4562-b3fc-2c963f66afa7"
        
        # Create multiple versions for the same rule
        version1 = create_version(test_file, rule_id=indicator_id, modified="2024-01-01T00:00:00.000Z")
        version2 = create_version(test_file, rule_id=indicator_id, modified="2024-01-02T00:00:00.000Z")
        
        file_id = test_file.id
        
        # Verify versions and file exist
        assert models.Version.objects.filter(rule_id=indicator_id).count() == 2
        assert models.File.objects.filter(id=file_id).exists()
        
        # Delete via API endpoint
        response = client.delete(f"/api/v1/base-rules/{indicator_id}/")
        assert response.status_code == status.HTTP_204_NO_CONTENT
        mock_delete_rule.assert_called_once_with(indicator_id)
        
        # All versions should be deleted
        assert models.Version.objects.filter(rule_id=indicator_id).count() == 0
        
        # File should be deleted because no versions reference it
        assert not models.File.objects.filter(id=file_id).exists()


    def test_rule_destroy_keeps_file_when_other_rules_reference_it_via_api(self, client, test_file, create_version, mock_delete_rule):
        """Test that destroying a rule via API doesn't delete the file if another rule's versions still reference it."""
        indicator_id_1 = "indicator--3fa85f64-5717-4562-b3fc-2c963f66afa6"
        indicator_id_2 = "indicator--4fa85f64-5717-4562-b3fc-2c963f66afa7"
        
        # Create versions for two different rules, both referencing the same file
        version_rule1_v1 = create_version(test_file, rule_id=indicator_id_1, modified="2024-01-01T00:00:00.000Z")
        version_rule1_v2 = create_version(test_file, rule_id=indicator_id_1, modified="2024-01-02T00:00:00.000Z")
        version_rule2_v1 = create_version(test_file, rule_id=indicator_id_2, modified="2024-01-01T00:00:00.000Z")
        
        file_id = test_file.id
        
        # Verify all versions exist
        assert models.Version.objects.filter(rule_id=indicator_id_1).count() == 2
        assert models.Version.objects.filter(rule_id=indicator_id_2).count() == 1
        assert models.File.objects.filter(id=file_id).exists()
        
        # Destroy rule 1 via API endpoint
        response = client.delete(f"/api/v1/base-rules/{indicator_id_1}/")
        assert response.status_code == status.HTTP_204_NO_CONTENT
        mock_delete_rule.assert_called_once_with(indicator_id_1)
        
        # Rule 1 versions should be deleted
        assert models.Version.objects.filter(rule_id=indicator_id_1).count() == 0
        
        # File should still exist because rule 2's version references it
        assert models.File.objects.filter(id=file_id).exists()
        
        # Rule 2 version should still exist
        assert models.Version.objects.filter(rule_id=indicator_id_2).count() == 1


class TestTasksView:
    def test_update__returns_job(self, client):
        resp = client.patch("/api/v1/tasks/sync-knowledgebases/cve/")
        assert resp.status_code == 201
        data = resp.json()
        assert data['type'] == 'sync-knowledgebase'
        assert data['extra']['knowledgebase'] == 'cve'
        ####

        resp = client.patch("/api/v1/tasks/sync-knowledgebases/enterprise-attack/")
        assert resp.status_code == 201
        data = resp.json()
        assert data['type'] == 'sync-knowledgebase'
        assert data['extra']['knowledgebase'] == 'enterprise-attack'
        ####

    def test_update__fails_on_bad_knowledgebase(self, client):
        resp = client.patch("/api/v1/tasks/sync-knowledgebases/capec/")
        assert resp.status_code == 404

    def test_update__calls_kbsync__sucess(self, client, celery_eager):
        with patch('siemrules.worker.tasks.kb_sync.run_on_kb_and_collection') as mock_kbsync:
            mock_kbsync.return_value = 150, 25
            resp = client.patch("/api/v1/tasks/sync-knowledgebases/cve/")
            assert resp.status_code == 201
            mock_kbsync.assert_called_once_with('siemrules_vertex_collection', 'cve', update_time=mock_kbsync.call_args[1]['update_time'])
            job = models.Job.objects.get(pk=resp.json()['id'])
            assert job.state == models.JobState.COMPLETED
            assert job.data['processed_items'] == 150
            assert job.data['updated_items'] == 25
            assert job.completion_time != None
    
    def test_update__calls_kbsync__fails(self, client, celery_eager):
        with patch('siemrules.worker.tasks.kb_sync.run_on_kb_and_collection') as mock_kbsync:
            mock_kbsync.side_effect = ValueError('dies')
            resp = client.patch("/api/v1/tasks/sync-knowledgebases/enterprise-attack/")
            assert resp.status_code == 201
            mock_kbsync.assert_called_once_with('siemrules_vertex_collection', 'enterprise-attack', update_time=mock_kbsync.call_args[1]['update_time'])
            assert resp.json()['state'] == models.JobState.FAILED
            job = models.Job.objects.get(pk=resp.json()['id'])
            assert job.completion_time != None