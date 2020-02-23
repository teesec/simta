#!/usr/bin/env bash
set -e
test=$1
if [[ "$test" = 'concrete' ]]; then
  python -m simta.simta exec binaries/task_storage_130 0x14c8 binaries/globaltask.elf \
    exec.securestorage.lifecycle.SecureStorageLifecycle 0x1618 0xff0 0x9cc 0xa04 0x990 0x904 0x155c
elif [[ "$test" = 'symbolic' ]]; then
  python -m simta.simta exec binaries/task_storage_130 0x14c8 binaries/globaltask.elf \
    exec.securestorage.lifecycleallsymbolic.SecureStorageLifecycleAllSymbolic 0x1618 0xff0 0x9cc 0xa04 0x990 0x904 0x155c
elif [[ "$test" = 'filter' ]]; then
  python -m simta.simta filter binaries/task_storage_160 0x158c binaries/globaltask.elf \
    exec.securestorage.lifecycletestfilter.SecureStorageLifecycleTestFilter 0x348 0x348 0x19e0 0x1a30 0x994 0xc64 0x7cc 0x7d4
fi
