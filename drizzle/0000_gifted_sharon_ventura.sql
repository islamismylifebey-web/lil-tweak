CREATE TABLE `workspace_projects` (
	`id` text PRIMARY KEY NOT NULL,
	`owner_email` text NOT NULL,
	`name` text NOT NULL,
	`description` text DEFAULT '' NOT NULL,
	`status` text DEFAULT 'planned' NOT NULL,
	`record_json` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_workspace_projects_owner_updated` ON `workspace_projects` (`owner_email`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_workspace_projects_owner_status` ON `workspace_projects` (`owner_email`,`status`);