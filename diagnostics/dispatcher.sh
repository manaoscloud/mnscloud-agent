#!/bin/sh
set -eu
umask 077
cd /

COMMAND="${SSH_ORIGINAL_COMMAND:-help}"
# Harmless textual normalization of habits seen in practice (diagnostics 4.0): a leading account
# name and a trailing stderr redirect. Nothing is evaluated; the rest must still match exactly.
COMMAND="${COMMAND#mns-diagnostics }"
case "$COMMAND" in
  *" 2>/dev/null") COMMAND="${COMMAND% 2>/dev/null}" ;;
  *" 2>&1") COMMAND="${COMMAND% 2>&1}" ;;
esac

collector() {
  exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /usr/bin/sudo -n -- /usr/bin/python3 -I \
    /usr/local/lib/mns-diagnostics/collector.py "$1"
}

# Match complete commands. Never evaluate client-provided shell expressions.
case "$COMMAND" in
  help|"")
    printf '%s\n' \
      "Allowed diagnostic commands (diagnostics 4.1):" \
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
      "  asterisk-odbc" \
      "  artifacts" \
      "  health" \
      "  agent" \
      "  host" \
      "  network" \
      "  timers" \
      "  edge" \
      "  access-summary [MINUTES]" \
      "  log-usage" \
      "  voip-summary" \
      "  schema-status"
    ;;
  identity)
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/id
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/hostname
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
    # Fixed third-party units plus every loaded mnscloud-* unit (glob matched by systemd itself).
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
      mnscloud-logs-config.service \
      freeradius.service \
      clickhouse-server.service \
      vector.service \
      pdns.service \
      pdns-recursor.service \
      dnsdist.service \
      'mnscloud-*'
    ;;
  config|config-check|logs|logs-text|versions|connectivity|asterisk-odbc|artifacts|health|agent|host|network|timers|edge|log-usage|voip-summary|schema-status)
    collector "$COMMAND"
    ;;
  access-summary)
    printf '\n' | collector access-summary
    ;;
  journal\ *|access-summary\ *)
    # Only the fixed operation name reaches sudo; its parameters travel on stdin and the collector
    # validates them (journal: fixed or mnscloud-* unit, 1-1440 minutes, err|warning|notice|info;
    # access-summary: 1-1440 minutes).
    operation="${COMMAND%% *}"
    printf '%s\n' "${COMMAND#* }" | collector "$operation"
    ;;
  *)
    printf '%s\n' "DENIED: Command is not in the diagnostic allowlist. Run 'help' for the list." >&2
    exit 126
    ;;
esac
