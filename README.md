

# General

## What is Guest Introspection for VMware NSX?
Guest Introspection for VMware NSX is a user space daemon installed inside Linux guest virtual machine for a proprietary NSX Guest Introspection product, for the purpose of providing network connection control and monitoring capability. This daemon uses capability provided by netfilter libraries (libnetfilter_queue and libnetfilter_conntrack) and netfilter kernel subsystem to offer network connection control and monitoring functionality.
 
Guest Introspection for VMware NSX provides following features:
               
  * Packet filtering (IPv4 and IPv6 over TCP/UDP) and controlling
  * Network connection monitoring (TCP and UDP)
 
### Dependencies 
Guest Introspection for VMware NSX requires libnetfilter_queue, libnetfilter_conntrack and netfilter kernel modules and libglib-2.0.


### Availabiltiy
Guest Introspection for VMware NSX is available on the following Linux distributions and versions:
 * Ubuntu 14.04 LTS 64-bit
 * RHEL 7 64-bit 
 * SLES 12 SP2 64-bit
 * CentOS 7 64 bit

### Build & Run

The following steps will work on most recent Linux distributions (Please install libnetfilter_queue, libnetfilter_conntrack and libglib-2.0 into appropriate path before building. For path, please refer makefile) :

* make
* sudo make install

Use the following step to start daemon
* /etc/init.d/vmw_conn_notifyd start

To change  syslog logging level of this daemon, please update DEBUG_LEVEL in /etc/vmw_conn_notify/vmw_conn_notify.conf. The accepted value of the logging level is from 0 to 7.

# Contributing

The guest-introspection-nsx project team welcomes contributions from the community. If you wish to contribute code and you have not
signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any
questions about the contributor license agreement (CLA) process, please refer to our [FAQ](https://cla.vmware.com/faq). 

## How can I get involved today?

You can get involved today in several different ways:

* Start using guest-introspection-nsx today and give us feedback.

* Suggest feature enhancements.

* Identify and submit bugs under issues section: https://github.com/vmware/guest-introspection-nsx/issues


## Will external developers be allowed to become committers to the project?

Yes. Initially, VMware engineers will be the only committers. As we roll out our development infrastructure, we will be looking to add external committers to the project as well.

## How can I submit code changes like bug fixes, patches, new features to the project?

Initially, you can submit bug fixes, patches and new features to the project development mailing list as attachments to e-mails or bug reports. To contribute source code, you will need to fill out a contribution agreement form as part of the submission process. We will have more details on this process shortly.


# License
The code is being released under GPL v2 license.
