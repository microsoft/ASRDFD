#!/bin/bash

export ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"
cd $ROOT/../src

sudo apt-get update
KERNEL_VMAX=6.5
aptcache_versions=$(sudo apt-cache search linux-headers-* | grep -i "Linux kernel headers for version" | egrep 'generic|azure' | egrep -v 'azure-edge|azure-cvm' | awk '{print $1}' | sed 's/linux-headers-//g' | sort -u)
for kernel in $aptcache_versions
do
    echo $kernel | grep "^${KERNEL_VMAX}" | grep -q "azure$" && {
        break
    }
done

echo "Building for kernel $kernel"

sudo apt-get install -y linux-headers-${kernel}
make all -f involflt.mak KDIR=/lib/modules/${kernel}/build TELEMETRY=yes
if [ $? -eq 0 ]; then
   echo "Build succeeded."
else
   echo "Build failed."
fi
