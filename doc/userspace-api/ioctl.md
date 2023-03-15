This driver module is well tested for distros/kernels mentioned at https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-support-matrix#linux. The driver exposes following interfaces in terms of IOTCLs to write the test code. The interfaces are as follows:

- IOCTL_INMAGE_START_FILTERING_DEVICE_V2<br />
  This IOCTL will be used to start filtering the writes on to a disk. It is going to save the actual make_request_fn and replaces with the driver's one to intercept the I/Os.

- IOCTL_INMAGE_STOP_FILTERING_DEVICE<br />
  This IOCTL will be used to stop filtering the writes on to a disk. It is going to restore the actual make_request_fn and unplugs from the I/O stack for this disk.

- IOCTL_INMAGE_UNSTACK_ALL<br />
  This IOCTL will stop the filtering all disks compared to previous IOCTL which works for one disk only.

- IOCTL_INMAGE_GET_DIRTY_BLOCKS_TRANS<br />
  This IOCTL will drain the data from the driver for a disk so that it can be applied to a local or remote disk to replicate the source disk.

- IOCTL_INMAGE_WAIT_FOR_DB_V2<br />
  This IOCTL helps in waiting at driver side for data to drain. If the above IOCTL get called frequently, very small chunks of data would be drained. So if the user thread waits in kernel using this IOCTL, the driver will wake-up the thread whenever data available for draining.

- IOCTL_INMAGE_COMMIT_DIRTY_BLOCKS_TRANS<br />
  Once the data drained using the IOCTL IOCTL_INMAGE_GET_DIRTY_BLOCKS_TRANS, the user thread can apply the data on to another disk. Afterwards, the user thread can intimate the driver through this IOCTL to throw away this data and not needed anymore. Otherwise, as part of draining, the driver will drain the same data again and again.

- IOCTL_INMAGE_CLEAR_DIFFERENTIALS<br />
  This IOCTL helps in throwing away all the captured data at the driver side.

- IOCTL_INMAGE_PROCESS_START_NOTIFY<br />
  The driver notes down the PID of this thread and this thread shouldn't close the file-descriptor of the driver handle till the drainer threads exist. That way, when this thread closes this file-descriptor, the driver can safely deal with the last data drained for which IOCTL IOCTL_INMAGE_COMMIT_DIRTY_BLOCKS_TRANS is not received.

- IOCTL_INMAGE_WAKEUP_ALL_THREADS<br />
  This IOCTL helps in waking-up all the drainer threads waiting at the driver side in kernel.

- IOCTL_INMAGE_FREEZE_VOLUME<br />
  Freezes one or more file-systems.

- IOCTL_INMAGE_THAW_VOLUME<br />
  Thaws the frozen file-system.

- IOCTL_INMAGE_TAG_VOLUME_V2<br />
  By using the above two IOCTLs, a bookmark can be introduced to recover the data up to this bookmark.

- IOCTL_INMAGE_TAG_COMMIT_V2<br />
  This IOCTL helps in to allow or drop the tag based the correctness above 3 IOCTLs.

- IOCTL_INMAGE_CREATE_BARRIER_ALL<br />
  Once this IOCTL issued, the interception routine will not allow any writes to go down the I/O stack. This way creates a barrier across all the disks to issue a book mark using the IOCTL IOCTL_INMAGE_TAG_VOLUME_V2 to create crash consistent recovery point.

- IOCTL_INMAGE_REMOVE_BARRIER_ALL<br />
  This IOCTL removes the barrier created using the previous IOCTL.

- IOCTL_INMAGE_IOBARRIER_TAG_VOLUME<br />
  This IOCTL creates barrier, issues the bookmark and removes the barrer for all filtered disks in a system.

**_NOTE:_** The last 7 IOCTLs can be used to achieve the crash/file-system consistent image of the disk(s) of the system.

- IOCTL_INMAGE_GET_PROTECTED_VOLUME_LIST<br />
  Lists all the filtered disks using this driver.

- IOCTL_INMAGE_GET_GLOBAL_STATS<br />
  Lists the statistics maintained at the driver level.

- IOCTL_INMAGE_GET_VOLUME_STATS<br />
  Lists the statistics for each filtered disk
