# The simple issuer: processes on this machine trade their Unix identity for a
# short-lived token from services.oidc-issuer.simple.url, signed by a key
# inside this machine's TPM2, which AWS STS can trust the same way it trusts
# GitHub Actions' tokens. The machine also publishes the issuer's discovery
# document and keys.
{ config, lib, ... }:
let
  cfg = config.services.oidc-issuer.simple;
  # The only key type the signer generates: ECDSA P-256, which AWS accepts as ES256.
  algorithm = "ES256";
in
{
  imports = [
    ./signer.nix
    ./publisher.nix
  ];

  options.services.oidc-issuer.simple = {
    enable = lib.mkEnableOption "the simple OIDC issuer: tokens for local users, signed by keys in this machine's TPM2";
    host = lib.mkOption {
      type = lib.types.str;
      example = "tokens.example.com";
      description = "Public hostname of the issuer, serving its discovery document over HTTPS.";
    };
    url = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "https://${cfg.host}";
      defaultText = lib.literalExpression ''"https://''${host}"'';
      description = ''
        Issuer identifier: the `iss` claim, and the provider URL a relying
        party is configured with. It fetches `<url>` + `discoveryPath`.
      '';
    };
    audience = lib.mkOption {
      type = lib.types.str;
      # the audience GitHub Actions and the AWS docs use for STS
      default = "sts.amazonaws.com";
      description = "`aud` claim of every token: the client ID registered with the relying party.";
    };
    discoveryPath = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      # fixed by OIDC Discovery; relying parties append it to the issuer URL
      default = "/.well-known/openid-configuration";
      description = "URL path of the discovery document.";
    };
    jwksPath = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "/.well-known/jwks.json";
      description = "URL path of the JSON Web Key Set.";
    };
    jwksCacheSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      readOnly = true;
      # AWS caches a JWKS for as long as its response allows
      default = 300;
      description = ''
        How long relying parties may cache the published JWKS: a new key is
        published this long before it signs.
      '';
    };
    jwksFile = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      internal = true;
      default = "/var/lib/oidc-issuer-jwks/jwks.json";
      description = "The published JWKS, which key rotation keeps current.";
    };
    discoveryDocument = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      description = "Contents of the discovery document.";
      # the fields AWS requires of a provider
      # (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
      default = {
        issuer = cfg.url;
        jwks_uri = "${cfg.url}${cfg.jwksPath}";
        response_types_supported = [ "id_token" ];
        subject_types_supported = [ "public" ];
        id_token_signing_alg_values_supported = [ algorithm ];
        claims_supported = [
          "iss"
          "sub"
          "aud"
          "iat"
          "exp"
          "jti"
        ];
      };
      defaultText = lib.literalMD "built from `url`, `jwksPath` and the signing algorithm";
    };
  };
}
