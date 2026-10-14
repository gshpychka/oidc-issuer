output "tunnel_id" {
  description = "ID of the tunnel, the TunnelID in its credentials file"
  value       = cloudflare_zero_trust_tunnel_cloudflared.this.id
}
