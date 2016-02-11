/*
 * Copyright (c) 2016  Herman J. Radtke III <herman@hermanradtke.com>
 *
 * This file is part of carp-rs.
 *
 * carp-rs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * carp-rs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with carp-rs.  If not, see <http://www.gnu.org/licenses/>.
 */

#define DEFINE_GLOBALS 1

#include <config.h>
#include "ucarp.h"
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void init_rand(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
#ifdef HAVE_SRANDOMDEV
    srandomdev();
#elif defined(HAVE_RANDOM)
    srandom((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#else
    srand((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#endif
}

int set_vaddr(const char *_vaddr)
{
    free(vaddr_arg);
    if (inet_pton(AF_INET, _vaddr, &vaddr) == 0) {
        logfile(LOG_ERR, "Invalid virtual address: [%s]", _vaddr);
        return 1;
    }
    vaddr_arg = strdup(_vaddr);
    return 0;
}

int set_mcast(const char *mcast)
{
    if (inet_pton(AF_INET, mcast, &mcastip) == 0) {
        logfile(LOG_ERR, "Invalid address: [%s]", mcast);
        return 1;
    }

    return 0;
}

int set_srcip(const char *_srcip)
{
    if (inet_pton(AF_INET, _srcip, &srcip) == 0) {
        logfile(LOG_ERR, "Invalid address: [%s]", _srcip);
        return 1;
    }

    return 0;
}

int set_vhid(unsigned char _vhid)
{
    if (_vhid > 255 || _vhid < 1) {
        logfile(LOG_ERR, "vhid must be between 1 and 255.");
        return 1;
    }
    vhid = (unsigned char) _vhid;
    return 0;
}

int set_interface(const char* _interface)
{
    if (_interface == NULL) {
        // Note: This requires root or it will segfault.
        interface = pcap_lookupdev(NULL);
        if (interface == NULL || *interface == 0) {
            logfile(LOG_ERR, "You must supply a network interface");
            return 1;
        }
    } else {
        free(interface);
        if ((interface = strdup(_interface)) == NULL) {
            return 1;
        }
    }
    logfile(LOG_INFO, "Using [%s] as a network interface", interface);
    return 0;
}

int set_password(const char *password)
{
    free(pass);
    if ((pass = strdup(password)) == NULL) {
        return 1;
    }

    return 0;
}

void set_advbase(unsigned char _advbase)
{
    advbase = _advbase;
}

void set_advskew(unsigned char _advskew)
{
    advskew = _advskew;
}

int set_dead_ratio(unsigned int _dead_ratio)
{
    if (_dead_ratio <= 0U) {
        logfile(LOG_ERR, "Dead ratio can't be zero");
        return 1;
    }
    dead_ratio = _dead_ratio;
    return 0;
}

void set_preempt(signed char _preempt)
{
    preempt = _preempt;
}

void set_neutral(signed char _neutral)
{
    neutral = _neutral;
}

void set_shutdown_at_exit(signed char _shutdown_at_exit)
{
    shutdown_at_exit = _shutdown_at_exit;
}

void set_ignoreifstate(signed char _ignoreifstate)
{
    ignoreifstate = _ignoreifstate;
}

void set_no_mcast(signed char _no_mcast)
{
    no_mcast = _no_mcast;
}

void register_up_callback(rust_callback cb)
{
    up_callback = cb;
}

void register_down_callback(rust_callback cb)
{
    down_callback = cb;
}

void trigger_up_callback()
{
    if (up_callback) {
        up_callback();
    }
}

void trigger_down_callback()
{
    if (down_callback) {
        down_callback();
    }
}

int libmain(struct Config *config)
{
#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        openlog("ucarp", LOG_PID, syslog_facility);
    }
#endif
    if (vhid == 0) {
        logfile(LOG_ERR, "You must supply a valid virtual host id");
        return 1;
    }
    if (pass == NULL || *pass == 0) {
        logfile(LOG_ERR, "You must supply a password");
        return 1;
    }
    if (advbase == 0 && advskew == 0) {
        logfile(LOG_ERR, "You must supply an advertisement time base");
        return 1;
    }
    if (srcip.s_addr == 0) {
        logfile(LOG_ERR, "You must supply a persistent source address");
        return 1;
    }
    if (vaddr.s_addr == 0) {
        logfile(LOG_ERR, "You must supply a virtual host address");
        return 1;
    }
    if (up_callback == NULL) {
        logfile(LOG_WARNING, "Warning: no callback registered when going up");
    }
    if (down_callback == NULL) {
        logfile(LOG_WARNING, "Warning: no callback registered when going down");
    }
    init_rand();
    if (docarp() != 0) {
        return 2;
    }

#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        closelog();
    }
#endif

    return 0;
}
