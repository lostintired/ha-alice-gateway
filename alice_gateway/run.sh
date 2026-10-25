#!/usr/bin/with-contenv bashio
# Запуск фильтра. mode=probe — зонд (всё 403 и журнал заголовков), mode=gateway — рабочий фильтр.
# В режиме gateway читает команды open/close из stdin (hassio.app_stdin) и сам закрывает окно привязки.
set -euo pipefail

CONF_DIR=/tmp/agw
FLAG=/data/window_open

MODE="$(bashio::config 'mode')"
bashio::log.info "alice-gateway mode=${MODE}, $(nginx -v 2>&1)"

if [[ "${MODE}" == "probe" ]]; then
    nginx -t -c /etc/alice-gateway/probe.conf
    exec nginx -c /etc/alice-gateway/probe.conf -g 'daemon off;'
fi
[[ "${MODE}" == "gateway" ]] || bashio::exit.nok "unknown mode ${MODE}"

HOST="$(bashio::config 'public_host')"
[[ "${HOST}" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] || bashio::exit.nok "public_host is not a valid host name"
MINUTES="$(bashio::config 'linking_minutes')"

mkdir -p "${CONF_DIR}"
sed "s/@PUBLIC_HOST@/${HOST}/g" /etc/alice-gateway/gateway.conf > "${CONF_DIR}/nginx.conf"

# extra_paths: точный путь или префикс со "*" в конце; методы через запятую (extra_map.sh).
for i in $(seq 0 $(( $(bashio::config 'extra_paths | length') - 1 ))); do
    echo "$(bashio::config "extra_paths[${i}].path") $(bashio::config "extra_paths[${i}].methods" | tr -d ' ')"
done | /etc/alice-gateway/extra_map.sh > "${CONF_DIR}/extra.map" || bashio::exit.nok "bad extra_paths"
bashio::log.info "extra_paths: $(grep -c . "${CONF_DIR}/extra.map" || true) rules"

window_close() {
    rm -f "${FLAG}"
    : > "${CONF_DIR}/window.map"
}
window_open() {
    date +%s > "${FLAG}"
    cp /etc/alice-gateway/window.map "${CONF_DIR}/window.map"
}
reload() {
    if nginx -t -q -c "${CONF_DIR}/nginx.conf"; then
        nginx -s reload -c "${CONF_DIR}/nginx.conf"
    else
        bashio::log.error "nginx config test failed, window closed"
        window_close
    fi
}

# После запуска окно всегда закрыто.
window_close
nginx -t -c "${CONF_DIR}/nginx.conf"
nginx -c "${CONF_DIR}/nginx.conf" -g 'daemon off;' &
NGINX_PID=$!

# Автозакрытие окна.
(
    while sleep 20; do
        opened="$(cat "${FLAG}" 2>/dev/null || true)"
        if [[ -n "${opened}" ]] && (( $(date +%s) - opened >= MINUTES * 60 )); then
            window_close
            reload
            bashio::log.info "linking window closed by timer"
        fi
    done
) &

# Команды из hassio.app_stdin: строка JSON ("open") или просто open.
# Фоновая команда без явного перенаправления читала бы /dev/null, поэтому stdin — через fd 3.
exec 3<&0
(
    while read -r line <&3; do
        cmd="$(jq -r 'if type == "string" then . else empty end' <<< "${line}" 2>/dev/null || echo "${line}")"
        case "${cmd}" in
            open) window_open; reload; bashio::log.info "linking window opened for ${MINUTES} min" ;;
            close) window_close; reload; bashio::log.info "linking window closed" ;;
            *) bashio::log.warning "unknown stdin command" ;;
        esac
    done
) &

wait "${NGINX_PID}"
