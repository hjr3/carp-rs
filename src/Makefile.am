#
# Copyright (c) 2016  Herman J. Radtke III <herman@hermanradtke.com>
#
# This file is part of carp-rs.
#
# carp-rs is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# carp-rs is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with carp-rs.  If not, see <http://www.gnu.org/licenses/>.
#

localedir = $(datadir)/locale

INCLUDES = -DLOCALEDIR=\"$(localedir)\"

noinst_LIBRARIES = \
	libcarp.a

libcarp_a_SOURCES = \
	ucarp.c \
	ucarp.h \
	carp.c \
	carp_p.h \
	ip_carp.h \
	crypto-sha1.c \
	crypto.h \
	crypto-sha1.h \
	globals.h \
	fillmac.c \
	fillmac.h \
	garp.c \
	garp.h \
	fakesnprintf.c \
	fakesnprintf.h \
	mysnprintf.c \
	mysnprintf.h \
	log.c \
	log.h \
	syslognames.h

libcarp_a_LIBADD = \
	$(LTLIBINTL)

