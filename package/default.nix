{
  lib,
  python3Packages,
}:
python3Packages.buildPythonApplication {
  pname = "oidc-issuer";
  version = "0.1.0";
  pyproject = true;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./pyproject.toml
      ./src
    ];
  };

  build-system = [ python3Packages.setuptools ];

  dependencies = [ python3Packages.cryptography ];

  pythonImportsCheck = [
    "oidc_issuer.signer"
    "oidc_issuer.client"
  ];
}
