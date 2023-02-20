with import <nixpkgs> {};
buildGoModule rec {
  name = "live-net-info";
  src = ./.;
  vendorSha256 = "sha256-2bZUAqACI9TdaGUWXYs0kBoLXhiv/WjCqsHm25U3v1g=";

  meta = with lib; {
    description = "Shows network information in real time";
    homepage = "https://github.com/Mic92/live-net-info";
    license = licenses.mit;
    maintainers = with maintainers; [ mic92 ];
  };
}
