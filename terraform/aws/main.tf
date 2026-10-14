# AWS side of the issuers: an IAM OIDC provider for each issuer host, so STS
# accepts its tokens, and roles that each trust exactly one subject's tokens.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

provider "aws" {
  # IAM is global; the provider still needs a region
  region = "us-east-1"
  # refuses to plan or apply against any other account
  allowed_account_ids = [var.aws_account_id]
}

locals {
  # role name -> the role, with the key of the issuer it trusts
  roles = merge([
    for issuer_key, issuer in var.issuers : {
      for name, role in issuer.roles : name => merge(role, { issuer = issuer_key })
    }
  ]...)
  # "<role name> <policy ARN>" -> the attachment
  policy_attachments = merge([
    for name, role in local.roles : {
      for arn in role.policy_arns : "${name} ${arn}" => { role = name, policy_arn = arn }
    }
  ]...)
}

resource "aws_iam_openid_connect_provider" "issuer" {
  for_each = var.issuers

  url            = "https://${each.value.host}"
  client_id_list = [each.value.audience]
  # No thumbprint_list: an issuer host behind Cloudflare serves a publicly
  # trusted certificate, which AWS checks against its own CA list, ignoring
  # thumbprints.
}

data "aws_iam_policy_document" "trust" {
  for_each = local.roles

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.issuer[each.value.issuer].arn]
    }
    # condition keys are the provider URL without https://, then the claim
    condition {
      test     = "StringEquals"
      variable = "${var.issuers[each.value.issuer].host}:aud"
      values   = [var.issuers[each.value.issuer].audience]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.issuers[each.value.issuer].host}:sub"
      values   = [each.value.subject]
    }
  }
}

resource "aws_iam_role" "role" {
  for_each = local.roles

  name                 = each.key
  description          = "Assumable with the token for ${each.value.subject} from ${var.issuers[each.value.issuer].host}"
  assume_role_policy   = data.aws_iam_policy_document.trust[each.key].json
  max_session_duration = each.value.max_session_duration
}

resource "aws_iam_role_policy_attachment" "role" {
  for_each = local.policy_attachments

  role       = aws_iam_role.role[each.value.role].name
  policy_arn = each.value.policy_arn
}
