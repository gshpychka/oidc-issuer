output "provider_arns" {
  description = "ARN of each issuer's IAM OIDC provider, by issuer key"
  value       = { for key, provider in aws_iam_openid_connect_provider.issuer : key => provider.arn }
}

output "role_arns" {
  description = "ARN of each role, by name: the --role-arn for oidc-token aws, or the role_arn of a web_identity_token_file profile"
  value       = { for name, role in aws_iam_role.role : name => role.arn }
}
