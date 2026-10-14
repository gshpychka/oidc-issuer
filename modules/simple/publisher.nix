# The simple issuer's publishing: serves the discovery document, built from
# the options, and the JWKS rotation keeps current, which AWS STS fetches to
# verify tokens.
#
# nginx serves them on a loopback port only root can bind. A Cloudflare tunnel
# (cloudflareTunnel) or any other HTTPS front for the issuer's host exposes
# them; the tunnel route passes only the two documents' paths.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.oidc-issuer.simple;
  # Below 1024, so only root can bind it: no other local user can stand in
  # for nginx (and serve its own JWKS to AWS) while nginx is down.
  port = 81;
  paths = [
    cfg.discoveryPath
    cfg.jwksPath
  ];
in
{
  options.services.oidc-issuer.simple = {
    origin = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "http://127.0.0.1:${toString port}";
      description = "Local HTTP origin of the documents, for whatever serves the issuer's host.";
    };
    cloudflareTunnel = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "my-tunnel";
      description = ''
        Name of a `services.cloudflared.tunnels` entry to route the issuer's
        host through, for the two document paths only.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.nginx = {
      enable = true;
      virtualHosts.oidc-discovery = {
        serverName = cfg.host;
        # the only server on this address, so no other vhost is reachable
        # through it whatever Host a request carries
        listen = [
          {
            addr = "127.0.0.1";
            inherit port;
          }
        ];
        # exact matches for the published documents; everything else 404s
        locations = {
          "= ${cfg.discoveryPath}".alias = pkgs.writeText "openid-configuration" (
            builtins.toJSON cfg.discoveryDocument
          );
          "= ${cfg.jwksPath}".alias = cfg.jwksFile;
          "/".return = "404";
        };
        extraConfig = ''
          default_type application/json;
          add_header Cache-Control "public, max-age=${toString cfg.jwksCacheSeconds}" always;
        '';
      };
    };

    services.cloudflared.tunnels = lib.mkIf (cfg.cloudflareTunnel != null) {
      ${cfg.cloudflareTunnel}.ingress.${cfg.host} = {
        service = cfg.origin;
        path = "^(${lib.concatMapStringsSep "|" lib.escapeRegex paths})$";
      };
    };
  };
}
