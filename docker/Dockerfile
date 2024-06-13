FROM ubuntu:20.04
#
# Setup redishoneypot
#
COPY RedisHoneyPot /opt/redishoneypot/
COPY dist/redis.conf /opt/redishoneypot/

# Start redishoneypot
WORKDIR /opt/redishoneypot

CMD ./RedisHoneyPot > /var/log/redishoneypot/redishoneypot.json 2>&1

# CMD tail -f
