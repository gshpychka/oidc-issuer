variable "cloudflare_api_token" {
  description = "Cloudflare API token with Zone:Read and DNS:Edit on the zone, and Cloudflare Tunnel:Edit on its account"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "ID of the Cloudflare zone the issuer hosts are in"
  type        = string
}

variable "tunnel_name" {
  description = "Name of the tunnel, as cloudflared and the NixOS modules' cloudflareTunnel options refer to it"
  type        = string
}

variable "hostnames" {
  description = "Issuer hosts to route through the tunnel, e.g. tokens.example.com for the simple issuer and spire.example.com for the SPIRE one"
  type        = set(string)
}
