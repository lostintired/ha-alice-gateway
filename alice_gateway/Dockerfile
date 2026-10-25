FROM ghcr.io/home-assistant/base:3.24-2026.10.1

RUN apk add --no-cache nginx \
    && nginx -v

COPY nginx/ /etc/alice-gateway/
COPY run.sh /run.sh
COPY extra_map.sh /etc/alice-gateway/extra_map.sh
RUN chmod a+x /run.sh /etc/alice-gateway/extra_map.sh

CMD ["/run.sh"]
