# The simple issuer's signing half: processes on this machine trade their Unix
# identity for a short-lived token from services.oidc-issuer.simple.url, which
# AWS STS can trust the same way it trusts GitHub Actions' tokens.
#
# - Identity: a token's subject is "<hostname>:<user>", the user the kernel
#   reports for the connecting process (SO_PEERCRED). Callers send nothing, so
#   there is no secret to steal and no request to parse. Any process running
#   as a client user can get that user's token.
# - Access: only users in services.oidc-issuer.simple.signer.clients. The
#   socket is restricted to their group, and the issuer checks the list again.
# - Key: ES256, generated inside this machine's TPM2, which refuses to export
#   it or duplicate it to another TPM2. On disk are only the key wrapped by
#   this TPM2's storage key, which nothing else can load, and the key's random
#   auth value, sealed with systemd-creds to both the TPM2 and the host key in
#   /var/lib/systemd: it only decrypts on this machine, booted through its own
#   Secure Boot chain (PCR 7). Each short-lived, sandboxed minting process
#   gets these from systemd and has the TPM2 sign through tpm2-tools. Root on
#   the running machine can sign too, but can't take the key away, so an
#   attacker's signing ends with their access to the machine.
#   Still rotate after a compromise: with copies of the files and the auth
#   value, any later TPM2 access on the machine is enough to sign again.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  issuerCfg = config.services.oidc-issuer.simple;
  cfg = issuerCfg.signer;
  inherit (config.networking) hostName;
  unitName = "oidc-issuer";
  stateDirectory = "/var/lib/${unitName}";
  socketPath = "/run/${unitName}/token.sock";
  clientGroup = "oidc-token";
  # What oidc-issuer-keygen writes to ${stateDirectory}/<kid>/, each file
  # handed to the minting process as the credential of the same name.
  keyFiles = {
    # the key's public area (TPM2B_PUBLIC)
    public = "key.pub";
    # the private key, encrypted by the TPM2's storage key (TPM2B_PRIVATE)
    private = "key.priv";
    # the auth value every use of the key needs, sealed with systemd-creds
    # under this name; systemd refuses to load it under any other
    auth = "key.auth";
  };

  tpmDevice = "/dev/tpmrm0";

  activeKey = lib.findFirst (key: key.kid == cfg.activeKid) null issuerCfg.publicKeys;

  issuerConfig = pkgs.writeText "${unitName}.json" (
    builtins.toJSON {
      # the issuer's name, also the prefix of every subject
      name = hostName;
      issuer = issuerCfg.url;
      inherit (issuerCfg) audience jwksCacheSeconds;
      inherit (cfg) clients;
      tokenLifetimeSeconds = cfg.tokenLifetime;
      activeKey = if activeKey == null then null else { inherit (activeKey) kid x y; };
      inherit stateDirectory keyFiles;
      systemdCreds = lib.getExe' config.systemd.package "systemd-creds";
      tpm2Tools = "${pkgs.tpm2-tools}/bin";
      # the kernel's TPM2 resource manager, which flushes whatever a process
      # loaded into the TPM2 when it exits
      tcti = "device:${tpmDevice}";
    }
  );

  package = pkgs.callPackage ../../package { };
  issuerTool = lib.getExe' package "oidc-issuer";

  keygen = pkgs.writeShellApplication {
    name = "oidc-issuer-keygen";
    text = ''exec ${issuerTool} keygen ${issuerConfig} "$@"'';
  };

  oidcToken = pkgs.writeShellApplication {
    name = "oidc-token";
    text = ''exec ${lib.getExe' package "oidc-token"} --socket ${socketPath} --unit ${unitName} "$@"'';
  };
in
{
  options.services.oidc-issuer.simple.signer = {
    enable = lib.mkEnableOption "signing OIDC tokens for local users";
    activeKid = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        kid of the published key to sign with, as printed by
        `oidc-issuer-keygen`. Null until the first key is published; the
        machine issues no tokens until then.
      '';
    };
    clients = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Unix users that may get a token for themselves, with subject
        "<hostname>:<user>". A new member's group applies from their next login.
      '';
    };
    tokenLifetime = lib.mkOption {
      type = lib.types.ints.between 60 3600;
      default = 300;
      description = ''
        Seconds a token stays valid. A token is only exchanged once, right
        after it is issued, so this only bounds how long a leaked one is useful.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = cfg.activeKid == null || activeKey != null;
            message = "services.oidc-issuer.simple.signer.activeKid ${toString cfg.activeKid} is not in services.oidc-issuer.simple.publicKeys, so relying parties could not verify its tokens.";
          }
          {
            assertion = lib.all (user: config.users.users ? ${user}) cfg.clients;
            message = "services.oidc-issuer.simple.signer.clients must name users.users entries.";
          }
        ];
        warnings = lib.optional (cfg.activeKid == null) ''
          services.oidc-issuer.simple.signer: no active signing key, so no tokens are issued yet.
          Run `sudo oidc-issuer-keygen` on ${hostName} and follow its output.
        '';

        environment.systemPackages = [
          keygen
          oidcToken
        ];
        systemd.tmpfiles.settings.${unitName}.${stateDirectory}.d = {
          user = "root";
          group = "root";
          mode = "0700";
        };
        users.groups.${clientGroup}.members = cfg.clients;
        # makes ${tpmDevice} accessible to its group, tssGroup
        security.tpm2.enable = true;
      }

      (lib.mkIf (cfg.activeKid != null) (
        let
          keyDirectory = "${stateDirectory}/${cfg.activeKid}";
        in
        {
          # One sandboxed process per connection, so no process holds the auth
          # value between requests.
          systemd.sockets.${unitName} = {
            description = "OIDC token issuer";
            wantedBy = [ "sockets.target" ];
            socketConfig = {
              ListenStream = socketPath;
              Accept = true;
              SocketUser = "root";
              SocketGroup = clientGroup;
              SocketMode = "0660";
              # bounds the instances a looping client can spawn; on a Unix
              # socket the per-source limit applies per peer UID
              MaxConnections = 16;
              MaxConnectionsPerSource = 4;
              RemoveOnStop = true;
            };
          };

          systemd.services."${unitName}@" = {
            description = "OIDC token issuer, one connection";
            # instances of failed refusals would otherwise pile up in `systemctl --failed`
            unitConfig.CollectMode = "inactive-or-failed";
            serviceConfig = {
              ExecStart = "${issuerTool} serve ${issuerConfig}";
              StandardInput = "socket";
              # logs go to the journal, never down the connection
              StandardOutput = "journal";
              StandardError = "journal";
              LoadCredential = map (name: "${name}:${keyDirectory}/${name}") [
                keyFiles.public
                keyFiles.private
              ];
              LoadCredentialEncrypted = "${keyFiles.auth}:${keyDirectory}/${keyFiles.auth}";
              # bounds a stuck instance; a normal one answers in about a second,
              # but a slow TPM2 can take several
              RuntimeMaxSec = 30;

              DynamicUser = true;
              # No PrivateUsers=: inside a user namespace every caller's UID
              # reads as nobody, and SO_PEERCRED would identify no one.
              PrivateNetwork = true;
              IPAddressDeny = "any";
              RestrictAddressFamilies = "AF_UNIX";
              CapabilityBoundingSet = "";
              NoNewPrivileges = true;
              # The TPM2 resource manager is the only device, reached through its
              # group. The group grants the whole TPM2 (other keys, extending
              # PCRs), which is why nothing a caller sends is ever read.
              PrivateDevices = true;
              BindPaths = [ tpmDevice ];
              DeviceAllow = [ "${tpmDevice} rw" ];
              SupplementaryGroups = [ config.security.tpm2.tssGroup ];
              ProtectSystem = "strict";
              ProtectHome = true;
              ProtectClock = true;
              ProtectHostname = true;
              ProtectKernelLogs = true;
              ProtectKernelModules = true;
              ProtectKernelTunables = true;
              ProtectControlGroups = true;
              ProcSubset = "pid";
              LockPersonality = true;
              MemoryDenyWriteExecute = true;
              RestrictNamespaces = true;
              RestrictRealtime = true;
              RestrictSUIDSGID = true;
              SystemCallArchitectures = "native";
              SystemCallFilter = [
                "@system-service"
                "~@privileged @resources"
              ];
              UMask = "0077";
            };
          };
        }
      ))
    ]
  );
}
