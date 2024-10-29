# SPDX-License-Identifier: GPL-2.0-only

# Copyright (C) 2022 Microsoft Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

ifeq (, $(WORKING_DIR))
	WORKING_DIR=${shell pwd}
endif

ifeq (, ${BLD_INVOLFLT})
	BLD_INVOLFLT=bld_involflt
endif

BLD_DIR=${WORKING_DIR}/${BLD_INVOLFLT}/

.PHONY: all clean

all:
	@rm -rf ${BLD_INVOLFLT}
	@rm -rf ${BLD_DIR}
	@mkdir -p ${BLD_DIR}
	@cp ${WORKING_DIR}/*.[ch] ${BLD_DIR}/
	@cp ${WORKING_DIR}/Makefile ${BLD_DIR}/
	@cp ${WORKING_DIR}/uapi/*.[ch] ${BLD_DIR}/
	@ln -s ${BLD_DIR} ${BLD_INVOLFLT}
	$(MAKE) debug=$(debug) KDIR=$(KDIR) WORKING_DIR=${WORKING_DIR} BLD_DIR=${BLD_DIR} TELEMETRY=${TELEMETRY}

clean:
	@rm -rf ${BLD_INVOLFLT}
	@rm -rf ${BLD_DIR}
