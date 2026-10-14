# The simple issuer's public face: its URL, its public keys, and the documents
# a relying party (AWS STS) fetches to verify tokens. The signer and the
# publisher may run on different machines; each of them sets these values.
{ config, lib, ... }:
let
  cfg = config.services.oidc-issuer.simple;
  # The only key type the signer generates: ECDSA P-256, which AWS accepts as ES256.
  algorithm = "ES256";
in
{
  options.services.oidc-issuer.simple = {
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
        How long relying parties may cache the published JWKS. A newly
        published key is only safe to sign with once this has passed since
        the deploy that published it.
      '';
    };
    publicKeys = lib.mkOption {
      default = [ ];
      description = ''
        Public halves of the signing keys, published in the JWKS. Entries are
        printed by `sudo oidc-issuer-keygen` on the signing machine. Keep a
        retired key listed until the tokens it signed have expired.
      '';
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            kid = lib.mkOption {
              type = lib.types.str;
              description = "Key ID: the RFC 7638 thumbprint of the key.";
            };
            x = lib.mkOption {
              type = lib.types.str;
              description = "P-256 public point x coordinate, base64url.";
            };
            y = lib.mkOption {
              type = lib.types.str;
              description = "P-256 public point y coordinate, base64url.";
            };
          };
        }
      );
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
    jwks = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      description = "Contents of the JSON Web Key Set.";
      default.keys = map (key: {
        inherit (key) kid x y;
        kty = "EC";
        crv = "P-256";
        alg = algorithm;
        use = "sig";
      }) cfg.publicKeys;
      defaultText = lib.literalMD "built from `publicKeys`";
    };
  };

  config.assertions = [
    {
      assertion = lib.allUnique (map (key: key.kid) cfg.publicKeys);
      message = "services.oidc-issuer.simple.publicKeys: every kid must be unique.";
    }
    {
      # every published key can sign tokens a relying party accepts, and an
      # extra one is easy to miss in review; rotation needs at most the old and new
      assertion = lib.length cfg.publicKeys <= 2;
      message = "services.oidc-issuer.simple.publicKeys: at most two keys (the active one and the one it replaces).";
    }
  ];
}
