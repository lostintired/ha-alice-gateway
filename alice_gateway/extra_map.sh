#!/bin/bash
# Строки "путь методы" из stdin (методы через запятую) -> правила map для nginx в stdout.
# Путь — точный или префикс со "*" в конце. Неверная строка — выход 1, правила не выводятся.
set -euo pipefail
out=""
n=0
while read -r path methods; do
    [[ -z "${path}" ]] && continue
    n=$((n + 1))
    prefix=0
    if [[ "${path}" == *'*' ]]; then prefix=1; path="${path%\*}"; fi
    if ! [[ "${path}" =~ ^(/[A-Za-z0-9_.-]+)+/?$ ]] || [[ "${path}" =~ (^|/)\.\.?(/|$) ]] \
        || { (( ! prefix )) && [[ "${path}" == */ ]]; }; then
        echo "extra_paths #${n}: bad path" >&2; exit 1
    fi
    esc="${path//./[.]}"
    IFS=',' read -ra list <<< "${methods}"
    (( ${#list[@]} )) || { echo "extra_paths #${n}: no methods" >&2; exit 1; }
    for m in "${list[@]}"; do
        m="${m// /}"
        [[ "${m}" =~ ^(GET|HEAD|POST|PUT|PATCH|DELETE)$ ]] || { echo "extra_paths #${n}: bad method" >&2; exit 1; }
        if (( prefix )); then
            out+="\"~^${m} ${esc}[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*\$\" 1;"$'\n'
        else
            out+="\"~^${m} ${esc}\$\" 1;"$'\n'
        fi
    done
done
printf '%s' "${out}"
