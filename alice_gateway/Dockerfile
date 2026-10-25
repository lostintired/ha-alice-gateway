FROM ghcr.io/home-assistant/base:3.24-2026.10.1

RUN apk add --no-cache nginx \
    && nginx -v

COPY nginx/ /etc/alice-gateway/
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
