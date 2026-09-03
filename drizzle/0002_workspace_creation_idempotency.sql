PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_workspace_projects` (
	`id` text PRIMARY KEY NOT NULL,
	`owner_email` text NOT NULL,
	`name` text NOT NULL,
	`description` text DEFAULT '' NOT NULL,
	`status` text DEFAULT 'planned' NOT NULL,
	`record_json` text NOT NULL,
	`create_idempotency_key` text,
	`create_request_digest` text,
	`create_complete` integer DEFAULT true NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT "workspace_projects_create_complete_check" CHECK("__new_workspace_projects"."create_complete" in (0,1))
);
--> statement-breakpoint
INSERT INTO `__new_workspace_projects`("id", "owner_email", "name", "description", "status", "record_json", "create_idempotency_key", "create_request_digest", "create_complete", "created_at", "updated_at") SELECT "id", "owner_email", "name", "description", "status", "record_json", NULL, NULL, true, "created_at", "updated_at" FROM `workspace_projects`;--> statement-breakpoint
DROP TABLE `workspace_projects`;--> statement-breakpoint
ALTER TABLE `__new_workspace_projects` RENAME TO `workspace_projects`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `idx_workspace_projects_owner_updated` ON `workspace_projects` (`owner_email`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_workspace_projects_owner_status` ON `workspace_projects` (`owner_email`,`status`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_workspace_projects_owner_create_key` ON `workspace_projects` (`owner_email`,`create_idempotency_key`) WHERE "workspace_projects"."create_idempotency_key" is not null;
