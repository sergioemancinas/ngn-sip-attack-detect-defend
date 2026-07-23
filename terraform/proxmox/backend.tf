# Terraform state is kept in a GitLab-managed HTTP backend. Initialise with:
#
#   export GITLAB_ACCESS_TOKEN=<pat-with-api-scope>
#   export TF_STATE_NAME=default
#   terraform init \
#     -backend-config="address=https://<gitlab-host>/api/v4/projects/<project-id>/terraform/state/$TF_STATE_NAME" \
#     -backend-config="lock_address=https://<gitlab-host>/api/v4/projects/<project-id>/terraform/state/$TF_STATE_NAME/lock" \
#     -backend-config="unlock_address=https://<gitlab-host>/api/v4/projects/<project-id>/terraform/state/$TF_STATE_NAME/lock" \
#     -backend-config="username=<gitlab-username>" \
#     -backend-config="password=$GITLAB_ACCESS_TOKEN" \
#     -backend-config="lock_method=POST" \
#     -backend-config="unlock_method=DELETE" \
#     -backend-config="retry_wait_min=5"
#
# Any Terraform HTTP backend works; the GitLab-managed state API is one option.

terraform {
  backend "http" {}
}
