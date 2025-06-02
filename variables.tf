variable "project" {}
variable "environment" {}
variable "scw_organization_id" {}
variable "scw_project_id" {}
variable "gitlab_jwks_url" {
  default = "https://gitlab.com/.well-known/openid-configuration"
}
variable "oidc" {
  type = list(object({
    application_id:string
    aud:string
    sub:string
    session_length:number
  }))
}
