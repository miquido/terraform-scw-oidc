# scw-oidc <a href="https://miquido.com"><img align="right" src="https://cdn.miquido.dev/miquido-logo.png" width="150" /></a>

Terraform module that deploys a Scaleway serverless OIDC token exchange endpoint for GitLab CI — validates GitLab JWT tokens and issues temporary Scaleway API keys.

## Development

```bash
make init   # run once after cloning
make readme # regenerate README.md
make lint   # lint terraform code
```

## Usage

```hcl
module "scw_oidc" {
  source = "git::https://gitlab.com/miquido/scw-oidc.git"

  project             = "myproject"
  environment         = "production"
  scw_organization_id = "your-organization-id"
  scw_project_id      = "your-project-id"
  scw_region          = "fr-par"

  oidc = [
    {
      application_id = "your-iam-application-id"
      aud            = "your-audience"
      sub            = "project_path:miquido/*"
      session_length = 3600
    }
  ]

  # Optional
  gitlab_jwks_url = "https://gitlab.com/.well-known/openid-configuration"
  function_domain = null
}
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_scaleway"></a> [scaleway](#requirement\_scaleway) | 2.53.0 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_scaleway"></a> [scaleway](#provider\_scaleway) | 2.53.0 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [scaleway_function.main](https://registry.terraform.io/providers/scaleway/scaleway/2.53.0/docs/resources/function) | resource |
| [scaleway_function_domain.oidc](https://registry.terraform.io/providers/scaleway/scaleway/2.53.0/docs/resources/function_domain) | resource |
| [scaleway_function_namespace.main](https://registry.terraform.io/providers/scaleway/scaleway/2.53.0/docs/resources/function_namespace) | resource |
| [scaleway_iam_api_key.oidc](https://registry.terraform.io/providers/scaleway/scaleway/2.53.0/docs/resources/iam_api_key) | resource |
| [scaleway_iam_application.oidc](https://registry.terraform.io/providers/scaleway/scaleway/2.53.0/docs/resources/iam_application) | resource |
| [scaleway_iam_policy.oidc_iam_access](https://registry.terraform.io/providers/scaleway/scaleway/2.53.0/docs/resources/iam_policy) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_environment"></a> [environment](#input\_environment) | n/a | `any` | n/a | yes |
| <a name="input_function_domain"></a> [function\_domain](#input\_function\_domain) | Function domain | `string` | `null` | no |
| <a name="input_gitlab_jwks_url"></a> [gitlab\_jwks\_url](#input\_gitlab\_jwks\_url) | n/a | `string` | `"https://gitlab.com/.well-known/openid-configuration"` | no |
| <a name="input_oidc"></a> [oidc](#input\_oidc) | n/a | <pre>list(object({<br/>    application_id:string<br/>    aud:string<br/>    sub:string<br/>    session_length:number<br/>  }))</pre> | n/a | yes |
| <a name="input_project"></a> [project](#input\_project) | n/a | `any` | n/a | yes |
| <a name="input_scw_organization_id"></a> [scw\_organization\_id](#input\_scw\_organization\_id) | n/a | `any` | n/a | yes |
| <a name="input_scw_project_id"></a> [scw\_project\_id](#input\_scw\_project\_id) | n/a | `any` | n/a | yes |
| <a name="input_scw_region"></a> [scw\_region](#input\_scw\_region) | n/a | `string` | n/a | yes |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_oidc_endpoint"></a> [oidc\_endpoint](#output\_oidc\_endpoint) | n/a |
<!-- END_TF_DOCS -->

## License

[MIT](LICENSE)