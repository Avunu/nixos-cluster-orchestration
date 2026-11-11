# lib/notify-email.nix — `send-notification-email <subject> <body>` via the
# Cloudflare Email Sending API. A function, not a module:
#
#   import ./lib/notify-email.nix { inherit pkgs; accountId = "…"; from = "…"; recipients = [ … ]; }
#
# The token is read at runtime -- from $NOTIFY_EMAIL_TOKEN_FILE, else
# the systemd credential `cf-email-token` -- never from the store. `to` is a
# single address per Cloudflare's schema, so it sends one request per recipient.
# `apiBase` is overridable so tests can point it at a stub and assert the
# request shape (tests/alerting.nix).
{
  pkgs,
  accountId,
  from,
  recipients,
  apiBase ? "https://api.cloudflare.com/client/v4",
}:
pkgs.writeShellApplication {
  name = "send-notification-email";
  runtimeInputs = with pkgs; [
    coreutils
    curl
    jq
  ];
  # A one-recipient list is a single static word to shellcheck.
  excludeShellChecks = [ "SC2043" ];
  text = ''
    SUBJECT="''${1:?usage: send-notification-email <subject> <body>}"
    BODY="''${2:?usage: send-notification-email <subject> <body>}"
    TOKEN_FILE="''${NOTIFY_EMAIL_TOKEN_FILE:-''${CREDENTIALS_DIRECTORY:-/nonexistent}/cf-email-token}"
    API_TOKEN=$(cat "$TOKEN_FILE")

    rc=0
    for recipient in ${pkgs.lib.escapeShellArgs recipients}; do
      PAYLOAD=$(jq -n --arg from ${pkgs.lib.escapeShellArg from} --arg to "$recipient" \
        --arg sub "$SUBJECT" --arg body "$BODY" \
        '{ from: $from, to: $to, subject: $sub, text: $body }')
      if ! curl -fsS --max-time 30 -X POST \
          "${apiBase}/accounts/${accountId}/email/sending/send" \
          -H "Authorization: Bearer $API_TOKEN" \
          -H "Content-Type: application/json" \
          -d "$PAYLOAD" >/dev/null; then
        echo "send-notification-email: delivery to $recipient failed" >&2
        rc=1
      fi
    done
    exit "$rc"
  '';
}
