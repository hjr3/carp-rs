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

#include <config.h>
#include "ucarp.h"
#include "fillmac.h"
#include <sys/ioctl.h>
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif
#ifdef HAVE_NET_IF_DL_H
# include <net/if_dl.h>
#endif
#ifdef HAVE_NET_IF_TYPES_H
# include <net/if_types.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif
#ifndef HAVE_NET_IF_ARP_H
# include <net/if_arp.h>
#endif
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#ifdef PF_PACKET
# define HWINFO_DOMAIN PF_PACKET
#else
# define HWINFO_DOMAIN PF_INET
#endif
#ifdef SOCK_PACKET
# define HWINFO_TYPE SOCK_PACKET
#else
# define HWINFO_TYPE SOCK_DGRAM
#endif

int fill_mac_address(void)
{
    int s;

    if ((s = socket(HWINFO_DOMAIN, HWINFO_TYPE, 0)) == -1) {
        logfile(LOG_ERR, "Unable to open raw device: [%s]",
                strerror(errno));
        return -1;
    }
#ifdef SIOCGIFHWADDR
    {
        struct ifreq ifr;

        if (strlen(interface) >= sizeof ifr.ifr_name) {
            logfile(LOG_ERR, "Interface name too long");
            return -1;
        }
        strncpy(ifr.ifr_name, interface, sizeof ifr.ifr_name);
        if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0) {
            logfile(LOG_ERR,
                    "Unable to get hardware info about an interface: %s",
                    strerror(errno));
            (void) close(s);
            return -1;
        }
        switch (ifr.ifr_hwaddr.sa_family) {
        case ARPHRD_ETHER:
        case ARPHRD_IEEE802:
            break;
        default:
            logfile(LOG_ERR, "Unknown hardware type [%u]",
                    (unsigned int) ifr.ifr_hwaddr.sa_family);
        }
        memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, sizeof hwaddr);
    }
#elif defined(HAVE_GETIFADDRS)
    {
        struct ifaddrs *ifas;
        struct ifaddrs *ifa;
        struct sockaddr_dl *sadl;
        struct ether_addr *ea;

        if (getifaddrs(&ifas) != 0) {
            logfile(LOG_ERR, "Unable to get interface address: %s",
                    strerror(errno));
            return -1;
        }
        ifa = ifas;
        while (ifa != NULL) {
            if (strcmp(ifa->ifa_name, interface) == 0 &&
                ifa->ifa_addr->sa_family == AF_LINK) {
                sadl = (struct sockaddr_dl *) (void *) ifa->ifa_addr;
                if (sadl == NULL || sadl->sdl_type != IFT_ETHER ||
                    sadl->sdl_alen <= 0) {
                    logfile(LOG_ERR,
                            "Invalid media / hardware address for [%s]",
                            interface);
                    return -1;
                }
                ea = (struct ether_addr *) LLADDR(sadl);
                memcpy(hwaddr, ea, sizeof hwaddr);

                return 0;
            }
            ifa = ifa->ifa_next;
        }
        return -1;
    }
#elif defined(SIOCGLIFNUM)
    {
        struct lifconf lifc;
        struct lifnum lifn;
        struct lifreq *lifr;
        caddr_t *lifrspace;
        struct arpreq arpreq;

        lifn.lifn_flags = 0;
        lifn.lifn_family = AF_INET;
        if (ioctl(s, SIOCGLIFNUM, &lifn) < 0) {
            logfile(LOG_ERR, "ioctl SIOCGLIFNUM error");
            return -1;
        }
        if (lifn.lifn_count <= 0) {
            logfile(LOG_ERR, "No interface found");
            return -1;
        }
        lifc.lifc_family = lifn.lifn_family;
        lifc.lifc_len = lifn.lifn_count * sizeof *lifr;
        lifrspace = ALLOCA(lifc.lifc_len);
        lifc.lifc_buf = (caddr_t) lifrspace;
        if (ioctl(s, SIOCGLIFCONF, &lifc) < 0) {
            logfile(LOG_ERR, "ioctl SIOCGLIFCONF error");
            ALLOCA_FREE(lifrspace);
            return -1;
        }
        lifr = lifc.lifc_req;
        for(;;) {
            if (lifn.lifn_count <= 0) {
                logfile(LOG_ERR, "Interface [%s] not found"), interface;
                ALLOCA_FREE(lifrspace);
                return -1;
            }
            lifn.lifn_count--;
            if (strcmp(lifr->lifr_name, interface) == 0) {
                break;
            }
            lifr++;
        }
        memcpy(&arpreq.arp_pa, &lifr->lifr_addr, sizeof arpreq.arp_pa);
        ALLOCA_FREE(lifrspace);
        if (ioctl(s, SIOCGARP, &arpreq) != 0) {
            logfile(LOG_ERR, "Unable to get hardware info about [%s]",
                    interface);
            return -1;
        }
        memcpy(hwaddr, &arpreq.arp_ha.sa_data, sizeof hwaddr);
    }
#endif

    (void) close(s);

    return 0;
}
