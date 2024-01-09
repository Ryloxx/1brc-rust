{
  outputs = { self, nixpkgs, flake-utils }:

    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell
          {
            name = "1brc-challenge-rust";
            buildInputs = with pkgs; [
              rustup
            ];
          };
      });
}
