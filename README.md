# Azure Site Recovery Disk Filter Driver for Linux (ASRDFD)

* [Introduction](#introduction)
* [Licensing](#licensing)
* [Design](#design)
* [Contributing](#contributing)
* [Roadmap](#roadmap)
* [Telemetry](#telemetry)
* [Trademarks](#trademarks)

## Introduction

Azure Site Recovery Disk Filter Driver for Linux (ASRDFD) is a disk filter driver to capture any changes to the disk. It can be installed as a kernel module in Linux and is currently used to implement the changed block tracking functionality used in Microsoft's Azure Site Recovery (ASR) product.

The ASR product uses this module to achieve the disaster recovery and one can refer to the public documentation for ASR is available at https://learn.microsoft.com/en-us/azure/site-recovery/. The data tracked/captured at this module can be drained to user-space and can be used to replicate locally or to a remote site.

The eventual goal is to upstream the driver to the Linux code tree.

## Licensing

This project is licensed under the license [GPL-v2 only](./LICENSE.txt).

## Design

The design is captured at [Design](doc/design.md).

## Contributing

This file describes the steps to use the driver. For more information about how to contribute code to this project, please check the [CONTRIBUTING.md](CONTRIBUTING.md) file in this repository.

### How to build
``` bash
cd src
make -f involflt.mak KDIR=/lib/modules/<kernel version>/build
```

- To compile the driver with telemetry support, compile with "TELEMETRY=yes" option.
- For SLES12/15, have to pass the service pack level of the kernel for which the driver is getting built with option PATCH_LEVEL=\<ServicePack Number\>. For example, if the driver is getting built for a kernel which is been released for SLES12 SP3, so "PATCH_LEVEL=3" has to be passed as an argument to the above make command as the service pack is 3.
- The build will generate the driver module file "involflt.ko".

### How to install
Use the below command to load the driver module.
``` bash
insmod involflt.ko
```

### How to test

All the IOCTLs are defined at [IOCTLs](doc/userspace-api/ioctl.md) to write the test utility.

## Roadmap

As new Linux kernels are released, we intend to keep updating the driver code to ensure that the driver works with the latest kernel releases. By opensourcing this code, we can enable Linux distro vendors to support the driver functionality as soon as a new kernel version is released. Our eventual goal is to work towards contributing this driver to the upstream Linux code tree.

## Telemetry

Data Collection. The software may collect information about you and your use of the software and send it to Microsoft. Microsoft may use this information to provide services and improve our products and services. You may turn off the telemetry as described in the repository. There are also some features in the software that may enable you and Microsoft to collect data from users of your applications. If you use these features, you must comply with applicable law, including providing appropriate notices to users of your applications together with a copy of Microsoft’s privacy statement. Our privacy statement is located at https://go.microsoft.com/fwlink/?LinkID=824704. You can learn more about data collection and use in the help documentation and our privacy statement. Your use of the software operates as your consent to these practices.

### Instructions to turn off telemetry

The telemetry is disabled by default. Please refer to the section [How to build](#how-to-build) if telemetry needs to be enabled.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
