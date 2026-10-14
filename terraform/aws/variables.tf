variable "aws_account_id" {
  description = "The AWS account this configuration manages"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID."
  }
}

variable "issuers" {
  description = <<-EOT
    Issuers AWS trusts, each with the roles its tokens can assume, keyed by a
    name of your choosing. A role's subject is the token's exact `sub`:
    "<hostname>:<user>" for the simple issuer,
    "spiffe://<trust domain>/<hostname>/user/<user>" or
    ".../service/<unit>" for the SPIRE one. Role names are unique across
    issuers.
  EOT
  type = map(object({
    host     = string
    audience = optional(string, "sts.amazonaws.com")
    roles = map(object({
      subject              = string
      policy_arns          = optional(set(string), [])
      max_session_duration = optional(number, 3600)
    }))
  }))

  validation {
    condition     = length(flatten([for issuer in var.issuers : keys(issuer.roles)])) == length(distinct(flatten([for issuer in var.issuers : keys(issuer.roles)])))
    error_message = "Role names must be unique across issuers."
  }
}
