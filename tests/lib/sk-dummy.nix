# OpenSSH's own software security key (regress/misc/sk-dummy): a FIDO "authenticator"
# as a library, which ssh loads as its SecurityKeyProvider in place of a YubiKey.
# The key handle it writes into a private key file IS the private key, so a pair made
# with it once works wherever this library is, with nobody to touch anything.
#
# For the one question a VM cannot otherwise ask: whether the initrd's sshd accepts an
# operator's `sk-ssh-ed25519@openssh.com` key (tests/boot-fallback.py,
# initrd-ssh-accepts-a-fido2-key). The server needs none of this: it verifies an sk
# signature with what every sshd has.
{ pkgs }:
pkgs.openssh.overrideAttrs (old: {
  pname = "openssh-sk-dummy";
  doCheck = false;
  postBuild = (old.postBuild or "") + ''
    make regress/misc/sk-dummy/sk-dummy.so
  '';
  postInstall = (old.postInstall or "") + ''
    install -D regress/misc/sk-dummy/sk-dummy.so $out/lib/sk-dummy.so
  '';
})
