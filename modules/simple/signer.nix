# The simple issuer's signing: tokens for local users, and the keys that sign
# them.
#
# - Identity: a token's subject is "<hostname>:<user>", the user the kernel
#   reports for the connecting process (SO_PEERCRED). Callers send nothing, so
#   there is no secret to steal and no request to parse. Any process running
#   as a client user can get that user's token.
# - Access: only users in services.oidc-issuer.simple.clients. The socket is
#   restricted to their group, and the issuer checks the list again.
# - Keys: ES256, generated inside this machine's TPM2, which refuses to export
#   them or duplicate them to another TPM2. On disk are only each key wrapped by
#   this TPM2's storage key, which nothing else can load, and the key's random
#   auth value, sealed with systemd-creds to both the TPM2 and the host key in
#   /var/lib/systemd: it only decrypts on this machine, booted through its own
#   Secure Boot chain (PCR 7). Each short-lived, sandboxed minting process
#   gets the active key's files from systemd and has the TPM2 sign through
#   tpm2-tools. Root on the running machine can sign too, but can't take a key
#   away, so an attacker's signing ends with their access to the machine.
# - Rotation: oidc-issuer-rotate (a timer) generates, publishes, activates,
#   retires and deletes keys, and writes the JWKS the publisher serves.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.oidc-issuer.simple;
  inherit (config.networking) hostName;
  unitName = "oidc-issuer";
  rotateUnit = "${unitName}-rotate";
  stateDirectory = "/var/lib/${unitName}";
  jwksDirectory = dirOf cfg.jwksFile;
  socketPath = "/run/${unitName}/token.sock";
  clientGroup = "oidc-token";
  # symlink in stateDirectory to the active key's directory
  activeLink = "active";
  # file in stateDirectory whose presence asks for the active key's replacement
  replaceRequest = "replace-active";
  # What rotation writes to ${stateDirectory}/<kid>/, each file handed to the
  # minting process as the credential of the same name.
  keyFiles = {
    # the key's public area (TPM2B_PUBLIC)
    public = "key.pub";
    # the private key, encrypted by the TPM2's storage key (TPM2B_PRIVATE)
    private = "key.priv";
    # the auth value every use of the key needs, sealed with systemd-creds
    # under this name; systemd refuses to load it under any other
    auth = "key.auth";
    # the public half and lifecycle times
    metadata = "key.json";
  };
  activeKey = "${stateDirectory}/${activeLink}";

  tpmDevice = "/dev/tpmrm0";

  issuerConfig = pkgs.writeText "${unitName}.json" (
    builtins.toJSON {
      name = hostName;
      issuer = cfg.url;
      inherit (cfg) audience clients jwksCacheSeconds;
      tokenLifetimeSeconds = cfg.tokenLifetime;
      rotationIntervalSeconds = cfg.rotationInterval;
      inherit
        stateDirectory
        activeLink
        replaceRequest
        keyFiles
        ;
      inherit (cfg) jwksFile;
      systemdCreds = lib.getExe' config.systemd.package "systemd-creds";
      tpm2Tools = "${pkgs.tpm2-tools}/bin";
      # the kernel's TPM2 resource manager, which flushes whatever a process
      # loaded into the TPM2 when it exits
      tcti = "device:${tpmDevice}";
    }
  );

  package = pkgs.callPackage ../../package { };
  issuerTool = lib.getExe' package "oidc-issuer";

  rotateNow = pkgs.writeShellApplication {
    name = "oidc-issuer-rotate-now";
    text = ''
      # asks the next rotation for a new key, which signs once it is published
      install -m 0600 /dev/null ${stateDirectory}/${replaceRequest}
      # runs that rotation now
      systemctl start ${rotateUnit}.service
    '';
  };

  oidcToken = pkgs.writeShellApplication {
    name = "oidc-token";
    text = ''exec ${lib.getExe' package "oidc-token"} --socket ${socketPath} --unit ${unitName} "$@"'';
  };

  # Sandboxing shared by the minting and rotation processes.
  sandbox = {
    PrivateNetwork = true;
    IPAddressDeny = "any";
    RestrictAddressFamilies = "AF_UNIX";
    CapabilityBoundingSet = "";
    NoNewPrivileges = true;
    # The TPM2 resource manager is the only device. Access to it grants the
    # whole TPM2 (other keys, extending PCRs), which is why nothing a caller
    # sends is ever read.
    PrivateDevices = true;
    BindPaths = [ tpmDevice ];
    DeviceAllow = [ "${tpmDevice} rw" ];
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
in
{
  options.services.oidc-issuer.simple = {
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
    rotationInterval = lib.mkOption {
      type = lib.types.ints.between 3600 31536000;
      default = 604800;
      description = ''
        Seconds a key signs before a new key replaces it. Rotation also
        replaces a key that stops working, such as after a Secure Boot key or
        dbx update changes PCR 7.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (user: config.users.users ? ${user}) cfg.clients;
        message = "services.oidc-issuer.simple.clients must name users.users entries.";
      }
    ];

    environment.systemPackages = [
      rotateNow
      oidcToken
    ];
    systemd.tmpfiles.settings.${unitName} = {
      ${stateDirectory}.d = {
        user = "root";
        group = "root";
        mode = "0700";
      };
      ${jwksDirectory}.d = {
        user = "root";
        group = "root";
        mode = "0755";
      };
    };
    users.groups.${clientGroup}.members = cfg.clients;
    # makes ${tpmDevice} accessible to its group, tssGroup
    security.tpm2.enable = true;

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
      unitConfig = {
        # instances of failed refusals would otherwise pile up in `systemctl --failed`
        CollectMode = "inactive-or-failed";
        # rotation creates the first key
        ConditionPathExists = activeKey;
      };
      serviceConfig = sandbox // {
        ExecStart = "${issuerTool} serve ${issuerConfig}";
        StandardInput = "socket";
        # logs go to the journal, never down the connection
        StandardOutput = "journal";
        StandardError = "journal";
        LoadCredential = map (name: "${name}:${activeKey}/${name}") [
          keyFiles.public
          keyFiles.private
          keyFiles.metadata
        ];
        LoadCredentialEncrypted = "${keyFiles.auth}:${activeKey}/${keyFiles.auth}";
        # bounds a stuck instance; a normal one answers in about a second,
        # but a slow TPM2 can take several
        RuntimeMaxSec = 30;
        DynamicUser = true;
        # No PrivateUsers=: inside a user namespace every caller's UID
        # reads as nobody, and SO_PEERCRED would identify no one.
        SupplementaryGroups = [ config.security.tpm2.tssGroup ];
      };
    };

    systemd.services.${rotateUnit} = {
      description = "OIDC token issuer key rotation";
      # at boot and on deploy, so the first key exists right away
      wantedBy = [ "multi-user.target" ];
      serviceConfig = sandbox // {
        Type = "oneshot";
        # root: systemd-creds seals with the root-only host key; creates that
        # key when the machine has none yet
        ExecStartPre = "+${lib.getExe' config.systemd.package "systemd-creds"} setup";
        ExecStart = "${issuerTool} rotate ${issuerConfig}";
        ReadWritePaths = [
          stateDirectory
          jwksDirectory
        ];
        # a tmpfs, for the plaintext auth values
        RuntimeDirectory = rotateUnit;
        RuntimeDirectoryMode = "0700";
        PrivateTmp = true;
      };
    };
    systemd.timers.${rotateUnit} = {
      wantedBy = [ "timers.target" ];
      # the steps between key states take effect on the next run
      timerConfig.OnCalendar = "*:0/5";
    };
  };
}
