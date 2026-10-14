# The Cloudflare tunnel that serves the issuers' discovery documents, and a
# proxied DNS name for each issuer host routed through it. cloudflared on the
# publishing machine holds the tunnel's routes (the NixOS modules'
# cloudflareTunnel options) and its secret: the tunnel is created without
# tunnel_secret, so the secret exists only in the credentials file
# `cloudflared tunnel token --cred-file` writes.

terraform {
  required_version = ">= 1.6"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

data "cloudflare_zone" "this" {
  zone_id = var.cloudflare_zone_id
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "this" {
  account_id = data.cloudflare_zone.this.account.id
  name       = var.tunnel_name
  config_src = "local"
}

resource "cloudflare_dns_record" "issuer" {
  for_each = var.hostnames

  zone_id = var.cloudflare_zone_id
  name    = each.value
  content = "${cloudflare_zero_trust_tunnel_cloudflared.this.id}.cfargotunnel.com"
  type    = "CNAME"
  ttl     = 1 # automatic, as proxied records require
  proxied = true
  comment = "OIDC issuer discovery documents via ${var.tunnel_name}"
}
