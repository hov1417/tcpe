#!/usr/bin/env bash

mkdir /sys/fs/cgroup/client
chown -R hov:hov /sys/fs/cgroup/client
chmod o+w /sys/fs/cgroup/cgroup.procs
chmod o+w /sys/fs/cgroup/client/cgroup.procs
