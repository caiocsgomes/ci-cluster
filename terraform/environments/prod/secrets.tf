resource "aws_secretsmanager_secret" "gha_app_self_hosted_runner" {
  name = "gha-app-self-hosted-runner"
}

variable "gha_app_self_hosted_runner_secret" {
  type = object({
    github_app_id = ""
    github_app_installation_id = ""
    github_app_private_key = ""
  })
  type = map(string)
}

resource "aws_secretsmanager_secret_version" "gha_app_self_hosted_runner" {
  secret_id     = aws_secretsmanager_secret.gha_app_self_hosted_runner.id
  secret_string = jsonencode(var.gha_app_self_hosted_runner_secret)
}
