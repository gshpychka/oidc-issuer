# oidc-issuer

Short-lived OIDC tokens for the users and services of a NixOS machine. AWS STS
trusts them through an IAM OIDC provider, the same way it trusts GitHub Actions'
tokens, so the machine holds no long-lived AWS keys. Any other relying party
that accepts OIDC tokens works the same way.

The flake has two independent issuers, each with its own host, enable flags and
NixOS options. Deploy either one, or both side by side.

|                    | Simple (`services.oidc-issuer.simple`)                                                             | SPIRE (`services.oidc-issuer.spire`)                                                                 |
| ------------------ | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Who the caller is  | the Unix user the kernel reports for the connecting process (`SO_PEERCRED`)                        | SPIRE's workload attestation: the Unix user, or the systemd unit                                     |
| Token subject      | `<hostname>:<user>`                                                                                | `spiffe://<trust domain>/<hostname>/user/<user>` or `.../service/<unit>`                             |
| Signing key        | generated inside the TPM2, which refuses to export it                                              | SPIRE's disk key manager: a file only the server can read, rotated every 7 days                      |
| What the TPM2 does | holds the signing key                                                                              | proves to the SPIRE server that the agent runs on this machine (endorsement key hash)                |
| Key rotation       | by hand, with `oidc-issuer-keygen`                                                                 | automatic                                                                                            |
| Published keys     | a static JWKS built from the NixOS config, served by nginx on loopback                             | a live JWKS from SPIRE's `oidc-discovery-provider` on a Unix socket                                  |
| AWS hand-off       | `credential_process = oidc-token aws --role-arn …`                                                 | spiffe-helper keeps `$XDG_RUNTIME_DIR/spiffe/aws.jwt` fresh for a `web_identity_token_file` profile  |

Each issuer's discovery document and JWKS are public at `https://<host>`. The
modules route them through a Cloudflare tunnel that passes only those document
paths, so the machine accepts no inbound connections.

## How it works

### Simple

1. `oidc-token` connects to `/run/oidc-issuer/token.sock`, which only the
   `oidc-token` group (the users in `signer.clients`) can connect to. It sends
   nothing.
2. systemd starts a sandboxed `oidc-issuer@` instance for the connection. The
   instance reads the caller's UID from the kernel, checks it against
   `signer.clients`, has the TPM2 sign a JWT (`sub` `<hostname>:<user>`, 5
   minute lifetime), checks the signature against the published key, and
   replies with the token. Each issuance and refusal goes to the journal.
3. `oidc-token aws --role-arn <ARN>` trades the token for credentials with
   `AssumeRoleWithWebIdentity` and prints them in `credential_process` format.
4. STS fetches `https://<host>/.well-known/openid-configuration` and the JWKS it
   points to. Cloudflare passes those two paths through the tunnel to nginx on
   `127.0.0.1:81`.

The key is an ECDSA P-256 key the TPM2 generated with `fixedtpm|fixedparent`,
so it cannot leave that TPM2. On disk are only the key wrapped by the TPM2's
storage key and the key's random auth value, sealed with `systemd-creds` to the
TPM2 (PCR 7) and the host key in `/var/lib/systemd`. The signer and the
publisher are separate modules and can run on different machines.

### SPIRE

`spire-server` (loopback only) signs JWT-SVIDs with keys it rotates itself,
publishing each one days before it signs. `spire-agent` attests to the server
with the machine's TPM2, and identifies callers of its Workload API socket by
Unix user and systemd unit. `spire-entries` makes the server's registration
entries match `users` and `services`, deleting any other entry.
`oidc-discovery-provider` serves the discovery document and live JWKS on a Unix
socket. For each user in `users`, a spiffe-helper user service keeps a fresh
token for AWS in `$XDG_RUNTIME_DIR/spiffe/aws.jwt`.

## Requirements

- **NixOS 26.05 or later**, x86_64-linux or aarch64-linux. The modules run on
  your system's nixpkgs, and the SPIRE issuer builds on the upstream
  `services.spire` modules, which 26.05 is the first release to have.
- **A TPM 2.0**, reachable through the kernel's resource manager at
  `/dev/tpmrm0`.
  - Simple: ECC P-256 keys, and an owner hierarchy without an auth value (the
    Linux default, which `systemd-creds`' own TPM2 sealing also needs).
  - Simple: **Secure Boot on** (for example with
    [lanzaboote](https://github.com/nix-community/lanzaboote)). PCR 7 records
    the Secure Boot state and keys, so the sealed auth value unseals only under
    the machine's own Secure Boot chain.
  - SPIRE: the TPM2's endorsement key, whose hash identifies the machine.
- **A domain in a Cloudflare zone**, and:
  - an API token with Zone · Zone · Read and Zone · DNS · Edit on that zone,
    and Account · Cloudflare Tunnel · Edit on its account;
  - `cloudflared tunnel login`, once, for the origin certificate that fetches
    the tunnel's credentials;
  - no bot challenges on the issuer hosts: AWS fetches the documents
    unattended.
- **An AWS account**, and credentials that can create IAM OIDC providers and
  roles.
- **OpenTofu or Terraform**, 1.6 or later. `nix develop` in this repository
  gives you `tofu`, `cloudflared` and `aws`.
- **A secrets mechanism** for NixOS, such as sops-nix or agenix, to put the
  tunnel's credentials file on the machine.

## Deploying

The examples use `example.com`, a machine named `myhost`, a user `alice` and a
tunnel named `my-tunnel`. Run the Terraform steps in a clone of this
repository; each directory keeps its state in a local `terraform.tfstate`
unless you add a backend.

### 1. Add the flake

```nix
{
  inputs.oidc-issuer = {
    url = "github:gshpychka/oidc-issuer";
    inputs.nixpkgs.follows = "nixpkgs";
  };
}
```

and add `inputs.oidc-issuer.nixosModules.default` to the machine's modules
(`nixosModules.simple` or `nixosModules.spire` for just one issuer).

### 2. Cloudflare tunnel and DNS

```sh
cd terraform/cloudflare
export TF_VAR_cloudflare_api_token=<API token>
tofu init
tofu apply \
  -var cloudflare_zone_id=<zone ID> \
  -var tunnel_name=my-tunnel \
  -var 'hostnames=["tokens.example.com","spire.example.com"]'
```

This creates the tunnel and a proxied CNAME for each issuer host. The tunnel's
secret stays out of the Terraform state; fetch it into a credentials file with
the origin certificate:

```sh
cloudflared tunnel login   # once; writes ~/.cloudflared/cert.pem
cloudflared tunnel token --cred-file creds.json my-tunnel
```

Encrypt `creds.json` into your secrets, delete the plaintext, and run the tunnel
on the publishing machine:

```nix
{
  # sops-nix shown; any secrets mechanism that yields a file works
  sops.secrets.cloudflare-tunnel = {
    sopsFile = ./secrets/cloudflare-tunnel.json;
    format = "json";
    key = ""; # the whole file
  };

  services.cloudflared = {
    enable = true;
    tunnels.my-tunnel = {
      credentialsFile = config.sops.secrets.cloudflare-tunnel.path;
      default = "http_status:404";
    };
  };
}
```

The issuers' `cloudflareTunnel` options add their routes to this tunnel.

### 3a. The simple issuer

Enable both halves first, without a key:

```nix
{
  services.oidc-issuer.simple = {
    host = "tokens.example.com";
    signer = {
      enable = true;
      clients = [ "alice" ];
    };
    publisher = {
      enable = true;
      cloudflareTunnel = "my-tunnel";
    };
  };
}
```

Deploy, then create the signing key in the TPM2:

```sh
sudo oidc-issuer-keygen
```

It prints the key's public half. Publish it and sign with it:

```nix
{
  services.oidc-issuer.simple = {
    publicKeys = [
      {
        kid = "<kid>";
        x = "<x>";
        y = "<y>";
      }
    ];
    signer.activeKid = "<kid>";
  };
}
```

Deploy again. For the very first key both settings go in one deploy: no relying
party has cached a key set before step 4 registers the issuer. Check it:

```sh
curl https://tokens.example.com/.well-known/jwks.json
oidc-token claims   # as alice, in a login session that started after step 3a
```

To run the signer and the publisher on different machines, set `host` and
`publicKeys` on both, `signer` on the signing machine and `publisher` on the
publishing one.

### 3b. The SPIRE issuer

Read the TPM2's endorsement key hash:

```sh
sudo nix shell nixpkgs#spire-tpm-plugin -c get_tpm_pubhash
```

```nix
{
  services.oidc-issuer.spire = {
    enable = true;
    host = "spire.example.com";
    trustDomain = "example.com";
    tpmEkHash = "<printed hash>";
    users = [ "alice" ];
    # system services get their own identity, per unit
    services.backup.user = "backup";
    cloudflareTunnel = "my-tunnel";
  };
}
```

Deploy, then check it:

```sh
curl https://spire.example.com/keys
spire-agent api fetch jwt -audience sts.amazonaws.com   # as alice
```

spiffe-helper runs in each listed user's systemd instance, so it starts with
their first login session, or at boot with `users.users.<name>.linger = true`.

### 4. AWS

Describe each issuer and the roles its tokens may assume, one exact subject per
role, in `terraform/aws/issuers.auto.tfvars`:

```hcl
issuers = {
  simple = {
    host = "tokens.example.com"
    roles = {
      "myhost-alice" = {
        subject     = "myhost:alice"
        policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
      }
    }
  }
  spire = {
    host = "spire.example.com"
    roles = {
      "myhost-alice-spire" = {
        subject = "spiffe://example.com/myhost/user/alice"
      }
    }
  }
}
```

```sh
cd terraform/aws
tofu init
tofu apply -var aws_account_id=<12-digit account ID>   # with your usual AWS credentials
```

The `role_arns` output has each role's ARN. A role without `policy_arns` can
still run `aws sts get-caller-identity`, which proves the whole chain.

### 5. Use it

As `alice`, in `~/.aws/config`. The simple issuer:

```ini
[profile myhost]
region = us-east-1
credential_process = oidc-token aws --role-arn arn:aws:iam::<account>:role/myhost-alice
```

The SPIRE issuer:

```ini
[profile myhost-spire]
region = us-east-1
role_arn = arn:aws:iam::<account>:role/myhost-alice-spire
web_identity_token_file = /run/user/<alice's uid>/spiffe/aws.jwt
```

```sh
aws sts get-caller-identity --profile myhost
```

AWS CLIs and SDKs get fresh credentials from either profile on their own.
`oidc-token` also prints a bare token (`oidc-token`) or its claims
(`oidc-token claims`), and `oidc-token aws --region <region>` uses that
region's STS endpoint.

## Rotating the simple issuer's key

1. `sudo oidc-issuer-keygen` on the signing machine.
2. Add the printed entry to `publicKeys`, next to the current one, and deploy
   the publisher.
3. Wait 300 seconds (`jwksCacheSeconds`), so cached key sets include the new
   key, then set `signer.activeKid` to the new kid and deploy the signer.
4. Once `signer.tokenLifetime` has passed, remove the old entry and delete
   `/var/lib/oidc-issuer/<old kid>` on the signing machine.

Generate a new key after any of these:

- a Secure Boot key or dbx update, which changes PCR 7 and leaves the sealed
  auth value unusable;
- clearing the TPM2, which destroys the key;
- any compromise of root on the signing machine.

## Security notes

- **Every process of a user holds that user's identity.** Anything running as
  a client user can get that user's token, coding agents and scripts included.
  Scope each role to what all of that user's processes may do, and give
  automation its own user or, with SPIRE, its own systemd unit.
- **Root on the issuing machine can mint any of its subjects' tokens.** It can
  use the TPM2 key (simple) or the SPIRE server's key. Treat everything that
  leads to root as part of the trust base: sudo rules, SSH agent forwarding,
  Nix `trusted-users`. With the simple issuer, an attacker signs only while
  they keep access to the machine, but rotate after any compromise: copies of
  the key files and auth value sign again with any later access to the TPM2.
- **Whoever controls the issuer host's content controls the issuer.** Anyone
  who can change the issuer host's DNS or what the tunnel serves can publish
  their own JWKS and mint tokens for every role that trusts that provider.
  Guard the Cloudflare API token, the origin certificate and the tunnel
  credentials like the signing key.
- **One subject per role, matched exactly.** The Terraform matches `aud` and
  `sub` with `StringEquals`. Keep session durations short, and alert on
  `AssumeRoleWithWebIdentity` in CloudTrail.
- **Tokens live 5 minutes.** STS accepts a token more than once until it
  expires, so the lifetime bounds what a leaked token is worth.

## Layout

| Path                    | What it is                                                                     |
| ----------------------- | ------------------------------------------------------------------------------ |
| `package/`              | `oidc-issuer` (the signer and keygen) and `oidc-token` (the client), in Python |
| `modules/simple/`       | the simple issuer: `issuer.nix` (its public data), `signer.nix`, `publisher.nix` |
| `modules/spire.nix`     | the SPIRE issuer                                                               |
| `terraform/cloudflare/` | the tunnel and the issuer hosts' DNS records                                   |
| `terraform/aws/`        | the IAM OIDC providers and the roles that trust them                           |
