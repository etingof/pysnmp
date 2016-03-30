#!/usr/bin/env sh

set -e

for x in examples/hlapi/asyncore/sync/manager/cmdgen/*.py \
         examples/hlapi/asyncore/sync/agent/ntforg/*.py \
         examples/hlapi/asyncore/manager/cmdgen/*.py \
         examples/hlapi/asyncore/agent/ntforg/*.py \
         examples/v3arch/asyncore/manager/cmdgen/*.py \
         examples/v3arch/asyncore/agent/ntforg/*.py \
         examples/v1arch/asyncore/manager/cmdgen/*.py \
         examples/v1arch/asyncore/agent/ntforg/*.py \
         examples/smi/manager/*py \
         examples/smi/agent/*.py
do
    case "${x}" in
    *spoof*|*ipv6*)
        echo "skipping ${x}"
        continue
        ;;
    *)
        python "${x}"
        ;;
    esac
done