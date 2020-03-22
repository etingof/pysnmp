#!/bin/bash
#
# Stand up a local SNMP command responder, run all SNMP manager example
# scripts against it.
#
# Fail the entire script on any failure.
#

set -e

TEST_ROOT=$(cd $(dirname $0) >/dev/null 2>&1; pwd -P)
SCRIPT_ROOT=$(mktemp -d /tmp/pysnmp.XXXXXX)
SIMULATION_DATA_ROOT=$(mktemp -d /tmp/snmpsim.XXXXXX)

cp -r $TEST_ROOT/samples/* $SIMULATION_DATA_ROOT

for auth in none md5 sha sha224 sha256 sha384 sha512; do
  for priv in none des 3des aes aes128 aes192 aes192blmt aes256 aes256blmt; do
    if [ ${auth} = "none" -a ${priv} != "none" ]; then
      continue
    fi
    params="${params} --v3-user=usr-${auth}-${priv}"
    if [ ${auth} != "none" ]; then
      params="${params} --v3-auth-proto=${auth} --v3-auth-key=authkey1"
      if [ ${priv} != "none" ]; then
        params="${params} --v3-priv-proto=${priv} --v3-priv-key=privkey1"
      fi
    fi
  done
done

HOME=~ snmpsimd.py \
      --log-level=error \
      --v3-engine-id=80004fb805636c6f75644dab22cc \
      --agent-udpv6-endpoint="[::1]:1161" \
      --agent-udpv4-endpoint=127.0.0.1:1161 \
      --agent-udpv6-endpoint="[::1]:2161" \
      --agent-udpv4-endpoint=127.0.0.1:2161 \
      --agent-udpv6-endpoint="[::1]:3161" \
      --agent-udpv4-endpoint=127.0.0.1:3161 \
      --data-dir $SIMULATION_DATA_ROOT \
      ${params} &

SNMPSIMD_PID=$!

function cleanup()
{
    kill $SNMPSIMD_PID
    #rm -rf $SCRIPT_ROOT $SIMULATION_DATA_ROOT
}

trap cleanup EXIT

PYTHON=${1:-python}

for x in examples/hlapi/asyncore/sync/manager/cmdgen/*.py \
         examples/hlapi/asyncore/manager/cmdgen/*.py \
         examples/v3arch/asyncore/manager/cmdgen/*.py \
         examples/v1arch/asyncore/manager/cmdgen/*.py \
         examples/smi/manager/*py \
         examples/smi/agent/*.py; do

    case "${x}" in

    *spoof*)
        echo "skipping ${x}"
        continue
        ;;

    *)
        destdir=$SCRIPT_ROOT/$(dirname ${x})
        mkdir -p $destdir
        destfile=$(basename ${x})

        sed -e "s/'demo.snmplabs.com', 161/'127.0.0.1', 1161/g" \
            -e "s/'104\.236\.166\.95', 161/'127.0.0.1', 1161/g" \
            -e "s/'::1', 161/'::1', 1161/g" \
            -e "s/demo.snmplabs.com:161/127.0.0.1:1161/g" \
            -e "s/demo.snmplabs.com/127.0.0.1/g" \
            ${x} > $destdir/$destfile

        $PYTHON "$destdir/$destfile"
        ;;

    esac

done

echo "Ha! It works! \o/"
