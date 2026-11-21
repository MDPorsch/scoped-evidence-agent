# The collector image (docs/remote-live-design.md 4.4). Build it, read what it contains, then pin the DIGEST of what you built:
#
#   docker build -f docker/collector/Dockerfile -t scopedagent-collector:local .
#   docker image inspect --format '{{.Id}}' scopedagent-collector:local      # sha256:...
#   scoped-agent live run --image sha256:... ...                              # the ID; a tag is refused
#
# A locally built image has no repository digest (that exists only after a push), so it is named by its ID, which is a hash of its
# content. `name@sha256:<id>` would make Docker try to pull `name` from a registry. An image you pushed can be named name@sha256:<digest>.
#
# The base image is a moving tag, so the image you build is the thing you review and pin, not this file.
FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/scopedagent
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir ".[live]" \
 && python -c "import scopedagent.live.isolation, scopedagent.live.collector"

# `docker run --entrypoint python IMAGE -m scopedagent.live.isolation` is the only way the controller starts it: it installs the
# firewall as root, proves it, drops every privilege, and only then waits for a job.
USER root
ENTRYPOINT ["python", "-m", "scopedagent.live.isolation"]
