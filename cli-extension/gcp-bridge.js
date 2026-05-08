import { google } from 'googleapis';

export class GCPBridge {
  constructor() {
    this.auth = null;
    this.crm = null;
  }

  async initialize() {
    const oauth2Client = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      process.env.GMAIL_REDIRECT_URI
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.GMAIL_REFRESH_TOKEN
    });

    this.auth = oauth2Client;
    this.crm = google.cloudresourcemanager({ version: 'v1', auth: this.auth });
  }

  async listProjects() {
    const res = await this.crm.projects.list();
    return res.data.projects || [];
  }

  async getProjectIamPolicy(projectId) {
    const res = await this.crm.projects.getIamPolicy({
      resource: projectId
    });
    return res.data;
  }

  async auditProjectSecurity(projectId) {
    const policy = await this.getProjectIamPolicy(projectId);
    const warnings = [];

    // Basic audit: check for primitive roles (Owner, Editor, Viewer) which are often too broad
    const primitiveRoles = ['roles/owner', 'roles/editor', 'roles/viewer'];

    if (policy.bindings) {
        policy.bindings.forEach(binding => {
            if (primitiveRoles.includes(binding.role.toLowerCase())) {
                warnings.push(`Project "${projectId}" has primitive role "${binding.role}" assigned to: ${binding.members.join(', ')}. Consider using fine-grained IAM roles.`);
            }
        });
    }

    return {
        projectId,
        policy,
        warnings,
        score: Math.max(0, 100 - (warnings.length * 20))
    };
  }
}
