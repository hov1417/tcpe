#!/usr/bin/env bash

mkdir /sys/fs/cgroup/server
chown -R hov:hov /sys/fs/cgroup/server
chmod o+w /sys/fs/cgroup/cgroup.procs
chmod o+w /sys/fs/cgroup/server/cgroup.procs
