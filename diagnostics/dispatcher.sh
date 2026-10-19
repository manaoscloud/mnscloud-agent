#!/bin/sh
set -eu
umask 077
cd /

# Match complete commands. Never evaluate client-provided shell expressions.
case "${SSH_ORIGINAL_COMMAND:-help}" in
  help|"")
    printf '%s\n' \
      "Allowed diagnostic commands:" \
      "  identity" \
      "  memory" \
      "  disk" \
      "  uptime" \
      "  services" \
      "  config" \
      "  config-check" \
      "  logs" \
      "  logs-text" \
      "  journal UNIT [MINUTES] [PRIORITY]" \
      "  versions" \
      "  connectivity" \
      "  asterisk-odbc"
    ;;
  identity)
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
      /usr/bin/id
    ;;
  memory)
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
      /usr/bin/timeout 10 /usr/bin/free -h
    ;;
  disk)
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
      /usr/bin/timeout 10 /usr/bin/df -h -l
    ;;
  uptime)
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
      /usr/bin/timeout 10 /usr/bin/uptime
    ;;
  services)
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
      /usr/bin/timeout 15 /usr/bin/systemctl \
      --no-pager show \
      --property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts \
      nginx.service \
      mariadb.service \
      rabbitmq-server.service \
      mnscloud-api.service \
      mnscloud-app.service \
      mnscloud-workers.service \
      mnscloud-agent.service \
      asterisk.service \
      freeswitch.service \
      kamailio.service \
      opensips.service \
      rtpengine-daemon.service \
      mnscloud-media-heartbeat.service \
      coturn.service \
      mnscloud-turn-sync.service \
      mnscloud-webrtc-sync.service \
      mnscloud-authentication.service \
      mnscloud-authentication-config.service \
      mnscloud-openvault.service \
      mnscloud-openvault-tls-renew.service \
      mnscloud-webapps.service \
      mnscloud-webapps-sync.service \
      incus.service \
      mnscloud-grow-rootfs.service \
      mnscloud-logs-storage.service \
      mnscloud-logs-ingest.service \
      mnscloud-logs-config.service
    ;;
  config|config-check|logs|logs-text|versions|connectivity|asterisk-odbc)
    exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
      /usr/bin/sudo -n -- /usr/bin/python3 -I \
      /usr/local/lib/mns-diagnostics/collector.py "$SSH_ORIGINAL_COMMAND"
    ;;
  journal\ *)
    # Only the fixed `journal` operation reaches sudo; its parameters travel on stdin and the
    # collector validates them (fixed unit list, 1-1440 minutes, err|warning|notice|info).
    printf '%s\n' "${SSH_ORIGINAL_COMMAND#journal }" |
      /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
      /usr/bin/sudo -n -- /usr/bin/python3 -I \
      /usr/local/lib/mns-diagnostics/collector.py journal
    ;;
  *)
    printf '%s\n' "DENIED: Command is not in the diagnostic allowlist." >&2
    exit 126
    ;;
esac
