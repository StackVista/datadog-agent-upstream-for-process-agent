#!/usr/bin/env bash

set -ex

if ! stat /.dockerenv >/dev/null 2>&1; then
  echo "error: this script should run inside our docker image" >&2
  exit 1
fi

if ! type "rsync" > /dev/null; then
  apt install rsync -y --no-install-recommends
fi

if ! test -f /usr/local/bin/docker-compose; then
   curl -SL https://github.com/docker/compose/releases/download/v2.23.3/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
fi

# This command assumes the datadog agent to be mounted at /source-datadog-agent. To avoid outputting to that directory,
# we make a clone before running any commands
mkdir -p $WORKDIR
rsync -au "$SOURCEDIR"/. $WORKDIR
chown -R root:root $WORKDIR
cd $WORKDIR

# Adding a faux tag to make the build pass on the rpo with no tags
git config user.email "you@example.com"
git config user.name "Your Name"
git tag -a 7.0.0 -m 7.0.0 || true

mount -t debugfs none /sys/kernel/debug/ || true

invoke install-tools