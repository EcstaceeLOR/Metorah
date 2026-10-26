BEGIN;

DROP TRIGGER IF EXISTS migration_artifacts_classification_guard ON migration_artifacts;
DROP TRIGGER IF EXISTS artifact_objects_insert_guard ON artifact_objects;
DROP TRIGGER IF EXISTS artifact_objects_lifecycle_init ON artifact_objects;
DROP TRIGGER IF EXISTS artifact_lifecycle_update_guard ON artifact_lifecycle;
DROP TRIGGER IF EXISTS artifact_objects_append_only ON artifact_objects;
DROP TRIGGER IF EXISTS artifact_objects_no_truncate ON artifact_objects;
DROP TRIGGER IF EXISTS migration_artifacts_append_only ON migration_artifacts;
DROP TRIGGER IF EXISTS migration_artifacts_no_truncate ON migration_artifacts;
DROP TRIGGER IF EXISTS artifact_access_events_append_only ON artifact_access_events;
DROP TRIGGER IF EXISTS artifact_access_events_no_truncate ON artifact_access_events;
DROP TRIGGER IF EXISTS artifact_retention_events_append_only ON artifact_retention_events;
DROP TRIGGER IF EXISTS artifact_retention_events_no_truncate ON artifact_retention_events;

DROP FUNCTION IF EXISTS guard_migration_artifact_insert();
DROP FUNCTION IF EXISTS guard_artifact_object_insert();
DROP FUNCTION IF EXISTS initialize_artifact_lifecycle();
DROP FUNCTION IF EXISTS guard_artifact_lifecycle_update();

DROP TABLE IF EXISTS artifact_retention_events;
DROP TABLE IF EXISTS artifact_access_events;
DROP TABLE IF EXISTS artifact_lifecycle;
DROP TABLE IF EXISTS migration_artifacts;
DROP TABLE IF EXISTS artifact_objects;
DROP TABLE IF EXISTS artifact_retention_policies;

COMMIT;
