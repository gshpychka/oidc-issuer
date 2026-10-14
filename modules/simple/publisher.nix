# The simple issuer's publishing half: serves the discovery document and JWKS
# that AWS STS fetches to verify tokens. Both are static, built from
# services.oidc-issuer.simple, so this needs no access to the signer and can
# run on any machine.
#
# nginx serves them on a loopback port only root can bind. A Cloudflare tunnel
# (publisher.cloudflareTunnel) or any other HTTPS front for the issuer's host
# exposes them; the tunnel route passes only the two documents' paths.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  issuerCfg = config.services.oidc-issuer.simple;
  cfg = issuerCfg.publisher;
  # Below 1024, so only root can bind it: no other local user can stand in
  # for nginx (and serve its own JWKS to AWS) while nginx is down.
  port = 81;

  # URL path -> document
  documents = {
    ${issuerCfg.discoveryPath} = issuerCfg.discoveryDocument;
    ${issuerCfg.jwksPath} = issuerCfg.jwks;
  };

  webRoot = pkgs.linkFarm "oidc-discovery" (
    lib.mapAttrs' (
      path: document:
      lib.nameValuePair (lib.removePrefix "/" path) (
        pkgs.writeText (baseNameOf path) (builtins.toJSON document)
      )
    ) documents
  );
in
{
  options.services.oidc-issuer.simple.publisher = {
    enable = lib.mkEnableOption "publishing the simple issuer's discovery document and JWKS";
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
        serverName = issuerCfg.host;
        # the only server on this address, so no other vhost is reachable
        # through it whatever Host a request carries
        listen = [
          {
            addr = "127.0.0.1";
            inherit port;
          }
        ];
        root = webRoot;
        # exact matches for the published documents; everything else 404s
        locations = lib.genAttrs (map (path: "= ${path}") (lib.attrNames documents)) (_: { }) // {
          "/".return = "404";
        };
        extraConfig = ''
          default_type application/json;
          add_header Cache-Control "public, max-age=${toString issuerCfg.jwksCacheSeconds}" always;
        '';
      };
    };

    services.cloudflared.tunnels = lib.mkIf (cfg.cloudflareTunnel != null) {
      ${cfg.cloudflareTunnel}.ingress.${issuerCfg.host} = {
        service = cfg.origin;
        path = "^(${lib.concatMapStringsSep "|" lib.escapeRegex (lib.attrNames documents)})$";
      };
    };
  };
}
