#!/bin/bash -x

PROJECT="sniff"
HOSTS="192.168.1.180 192.168.1.181"
FILES="lib src test mix.* make.* *.bat *.sh"

remote() {
  for HOST in $HOSTS; do
    ssh $HOST mkdir -p .farm/$PROJECT
    rsync -r --delete $FILES $HOST:.farm/$PROJECT/
    #sourcing farm won't work
    ssh $HOST ".farm/$PROJECT/farm.sh local"
  done
}

local() {
  MIX="`which mix`"
  if [ "$(expr substr $(uname -s) 1 9)" == "CYGWIN_NT" ]; then
    MIX="$MIX.bat"
  fi
  SCRIPT=`realpath $0`
  cd `dirname "$SCRIPT"`
  #mix local.hex --force
  "$MIX" deps.get
  "$MIX" test
}

$@
