# Design

The interception of the I/O starts by replacing the actual make_request_fn pointer in request_queue for a disk and this allows the driver to filter the writes on to the disk based on the bio submitted for WRITE.. The actual make_request_fn pointer of a disk would be saved by the driver and will be used to unplug from the I/O stack at any later point of time to stop intercepting the I/Os for the disk. The core functionality of this driver is to capture the data or payload within the I/O vectors of a bio and this capturing will be performed once the write hits the disk, that is, in the path of completion of write in the interrupt context where bio_endio callback will be invoked for each submitted bio. In order to achieve this, the intercept route of driver does the following:<br />
1. Once a bio comes to the intercept routine of the driver, the driver checks if the bio is submitted for READ or WRITE. If it is a READ, then invokes the original make_request_fn to complete the READ. Otherwise, moves to the next step.
2. Saves the bi_endio and bi_private fields of bio and point to the driver's version so that the completion can end in the driver's routine and helps in getting the callback to driver's routine once the write completes. Invokes the original make_request_fn to send the write request down the I/O stack for completion.
3. On completion of write, the driver starts capturing the data in the bio to driver specific buffers if available, otherwise captures starting write offset of the disk and length of the write so that this information can be utilized to read the data from the disk at later point of time.
4. Once the driver captures the data inside the bio, the driver would restores the original bi_endio and bi_private fields of bio and invokes bi_endio to send the control to the owner of this bio.

The submission of write request flow will look like

			submit_bio
			     |
			     v
			make_request_fn
			     |
			     v
			flt_make_request_fn (driver's intercept routine)
			     |----------------------> Saves the bi_endio and bi_private fields of bio
			     |	                      Replaces with driver's routine inm_bio_endio
			     v
			make_request_fn (Original saved routine)

The completion of the same will look like

			inm_bio_endio (driver's completion routine)
                             |----------------------> Captures the data in bio and restores the bi_end_io and bi_provate fileds
                             v
                        bi_end_io

Starting 5.8 kernel, make_request_fn is not getting populated for all the disks and in 5.9 kernel, this pointer is completely removed. The driver has started replacing the queue_rq function pointer in blk_mq_ops of request_queue. This routine intercepts a request instead of bio and then loops over the bios in this request and performs the above operations.

It is clear that this module is capturing the data in the completion path of each write where the data associated with the write is already written to the disk or failed to write. This can be done in the driver's interception routine as well but that needs extra handling as the write may fail and in the mean time if the user-space drains and uses it. The whole workflow needs a mechanism to undo the captured data and it adds challenges to handle this scenario. And also how to handle the partial completion of write on to the disk. SO handling the capturing in the completion path.

This driver module captures the data in two modes:
- Data Mode: The driver captures the offset and size of the write involved by referring the bio object received in the completion routine. This mode also captures data/payload associated with the write by referreing to the bio vectors. This mode mandates the driver to reserve some memory as the driver can't just allocate all the memory which can impact the production system. For this purpose, the driver allocates 6.25% of RAM. Once this reserved memory exhausts, the driver moves to metadata mode of capturing.
- Metadata Mode: The driver captures the offset and size of the write involved only. When the drainer drains this kind of data, the drainer has to read the data from disk using the offset and size of the writes so far captured in this mode.

The driver maintains a bitmap file of granulariry 4k or 16k depneding on the size of the disk. The driver will start writing to the bitmap file once the number of writes captured in the metadata mode goes beyond certain limit and discards the captured writes. This way, the driver restricts the over utlization of production system's memory. This is referred to as Bitmap Mode.
