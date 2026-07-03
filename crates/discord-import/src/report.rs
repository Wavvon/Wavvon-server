//! Renders `import-report.txt` (docs/docs/discord-import.md §5): counts,
//! skips with reasons, warnings, and a PARTIAL banner if anything failed.
//! Pure string-building so it's testable without touching the hub.

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub roles_created: Vec<(String, String)>,
    pub roles_failed: Vec<(String, String)>,
    pub channels_created: Vec<(String, String)>,
    /// A channel skipped because its parent failed to create -- creating it
    /// anyway would silently flatten it to top-level, changing structure
    /// the operator didn't ask for.
    pub channels_skipped: Vec<(String, String)>,
    pub channels_failed: Vec<(String, String)>,
    pub overwrites_applied: usize,
    pub overwrites_skipped: Vec<(String, String, String)>,
    pub overwrites_failed: Vec<(String, String, String)>,
    /// Carried over verbatim from the manifest's `warnings` (export-time
    /// notes: skipped Discord channel kinds, member overwrites, possible
    /// allow/deny conflicts, text+voice merge suggestions).
    pub manifest_warnings: Vec<String>,
}

impl ApplyReport {
    pub fn had_failures(&self) -> bool {
        !self.roles_failed.is_empty()
            || !self.channels_failed.is_empty()
            || !self.channels_skipped.is_empty()
            || !self.overwrites_failed.is_empty()
            || !self.overwrites_skipped.is_empty()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();

        if self.had_failures() {
            out.push_str("=== PARTIAL: discord-import apply completed with failures ===\n\n");
        } else {
            out.push_str("=== discord-import apply completed successfully ===\n\n");
        }

        out.push_str(&format!("Roles created: {}\n", self.roles_created.len()));
        for (name, id) in &self.roles_created {
            out.push_str(&format!("  + {name} -> {id}\n"));
        }
        if !self.roles_failed.is_empty() {
            out.push_str(&format!("Roles failed: {}\n", self.roles_failed.len()));
            for (name, err) in &self.roles_failed {
                out.push_str(&format!("  ! {name}: {err}\n"));
            }
        }

        out.push_str(&format!(
            "\nChannels created: {}\n",
            self.channels_created.len()
        ));
        for (name, id) in &self.channels_created {
            out.push_str(&format!("  + {name} -> {id}\n"));
        }
        if !self.channels_skipped.is_empty() {
            out.push_str(&format!(
                "Channels skipped: {}\n",
                self.channels_skipped.len()
            ));
            for (name, reason) in &self.channels_skipped {
                out.push_str(&format!("  - {name}: {reason}\n"));
            }
        }
        if !self.channels_failed.is_empty() {
            out.push_str(&format!(
                "Channels failed: {}\n",
                self.channels_failed.len()
            ));
            for (name, err) in &self.channels_failed {
                out.push_str(&format!("  ! {name}: {err}\n"));
            }
        }

        out.push_str(&format!(
            "\nOverwrites applied: {}\n",
            self.overwrites_applied
        ));
        if !self.overwrites_skipped.is_empty() {
            out.push_str(&format!(
                "Overwrites skipped: {}\n",
                self.overwrites_skipped.len()
            ));
            for (channel, role_ref, reason) in &self.overwrites_skipped {
                out.push_str(&format!("  - {channel} / role {role_ref}: {reason}\n"));
            }
        }
        if !self.overwrites_failed.is_empty() {
            out.push_str(&format!(
                "Overwrites failed: {}\n",
                self.overwrites_failed.len()
            ));
            for (channel, role_ref, err) in &self.overwrites_failed {
                out.push_str(&format!("  ! {channel} / role {role_ref}: {err}\n"));
            }
        }

        if !self.manifest_warnings.is_empty() {
            out.push_str(&format!(
                "\nManifest warnings from export ({}):\n",
                self.manifest_warnings.len()
            ));
            for w in &self.manifest_warnings {
                out.push_str(&format!("  * {w}\n"));
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_report_has_no_partial_banner() {
        let mut report = ApplyReport::default();
        report
            .roles_created
            .push(("Raid Lead".to_string(), "id1".to_string()));
        report
            .channels_created
            .push(("Games".to_string(), "id2".to_string()));
        report.overwrites_applied = 1;

        let text = report.render();
        assert!(!report.had_failures());
        assert!(text.starts_with("=== discord-import apply completed successfully ==="));
        assert!(text.contains("Roles created: 1"));
        assert!(text.contains("Games -> id2"));
    }

    #[test]
    fn any_failure_triggers_partial_banner() {
        let mut report = ApplyReport::default();
        report
            .channels_failed
            .push(("general".to_string(), "500 error".to_string()));

        let text = report.render();
        assert!(report.had_failures());
        assert!(text.starts_with("=== PARTIAL"));
        assert!(text.contains("general: 500 error"));
    }

    #[test]
    fn skipped_child_of_failed_parent_also_triggers_partial() {
        let mut report = ApplyReport::default();
        report.channels_skipped.push((
            "raids".to_string(),
            "parent 'Games' failed to create".to_string(),
        ));

        assert!(report.had_failures());
        assert!(report.render().starts_with("=== PARTIAL"));
    }
}
