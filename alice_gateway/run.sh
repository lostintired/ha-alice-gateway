#!/usr/bin/with-contenv bashio
# Запуск фильтра: выбирает конфигурацию nginx по опции mode.
set -e

MODE="$(bashio::config 'mode')"
bashio::log.info "alice-gateway mode=${MODE}, $(nginx -v 2>&1)"

case "${MODE}" in
    probe) CONF=/etc/alice-gateway/probe.conf ;;
    *) bashio::exit.nok "unknown mode ${MODE}" ;;
esac

nginx -t -c "${CONF}"
exec nginx -c "${CONF}" -g 'daemon off;'
