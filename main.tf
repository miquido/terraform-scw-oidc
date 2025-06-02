resource "scaleway_function_namespace" "main" {
  name        = "${var.project}-${var.environment}-oidc"
  project_id  = var.scw_project_id
  description = "OIDC Function namespace"
}

resource scaleway_function main {
  name                         = "${var.project}-${var.environment}-oidc"
  namespace_id                 = scaleway_function_namespace.main.id
  runtime                      = "python313"
  handler                      = "main.handle"
  privacy                      = "public"
  timeout                      = 20
  zip_file                     = "${path.module}/func.zip"
  zip_hash                     = filesha256("${path.module}/func.zip")
  deploy                       = true
  secret_environment_variables = {
    SCW_SECRET_KEY : scaleway_iam_api_key.oidc.secret_key
  }
  environment_variables = {
    GITLAB_JWKS_URL : var.gitlab_jwks_url
    OIDC : jsonencode(var.oidc)
  }
}

resource "scaleway_iam_api_key" "oidc" {
  application_id = scaleway_iam_application.oidc.id
  description    = "Access to registry"
}

resource "scaleway_iam_application" "oidc" {
  name        = "${var.project}-${var.environment}-oidc"
  description = "Manage keys for OIDC"
}

resource scaleway_iam_policy "oidc_iam_access" {
  name           = "${var.project}-${var.environment}-oidc"
  description    = "gives cicd access to push to the registry and deploy"
  application_id = scaleway_iam_application.oidc.id
  rule {
    organization_id      = var.scw_organization_id
    permission_set_names = ["IAMManager"]
  }
}
