#!/usr/bin/env bash

while read pid; do echo "$pid" > /sys/fs/cgroup/cgroup.procs; done \
   < /sys/fs/cgroup/client/cgroup.procs
while read pid; do echo "$pid" > /sys/fs/cgroup/cgroup.procs; done \
   < /sys/fs/cgroup/server/cgroup.procs

rmdir /sys/fs/cgroup/client
rmdir /sys/fs/cgroup/server
