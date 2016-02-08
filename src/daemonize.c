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
#include "daemonize.h"
#include "ucarp.h"
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static unsigned int open_max(void)
{
    long z;

    if ((z = (long) sysconf(_SC_OPEN_MAX)) < 0L) {
        logfile(LOG_ERR, "_SC_OPEN_MAX");
        _exit(EXIT_FAILURE);
    }
    return (unsigned int) z;
}

static int closedesc_all(const int closestdin)
{
    int fodder;

    if (closestdin != 0) {
        (void) close(0);
        if ((fodder = open("/dev/null", O_RDONLY)) == -1) {
            return -1;
        }
        (void) dup2(fodder, 0);
        if (fodder > 0) {
            (void) close(fodder);
        }
    }
    if ((fodder = open("/dev/null", O_WRONLY)) == -1) {
        return -1;
    }
    (void) dup2(fodder, 1);
    (void) dup2(1, 2);
    if (fodder > 2) {
        (void) close(fodder);
    }
    return 0;
}

void dodaemonize(void)
{
    pid_t child;
    unsigned int i;

    /* Contributed by Jason Lunz - also based on APUI code, see open_max() */
    if (daemonize != 0) {
        if ((child = fork()) == (pid_t) -1) {
            logfile(LOG_ERR, "Unable to get in background: [fork: %s]",
                    strerror(errno));
            return;
        } else if (child != (pid_t) 0) {
            _exit(EXIT_SUCCESS);       /* parent exits */
        }
        if (setsid() == (pid_t) -1) {
            logfile(LOG_WARNING,
                    "Unable to detach from the current session: %s",
                    strerror(errno));  /* continue anyway */
        }

        /* Fork again so we're not a session leader */
        if ((child = fork()) == (pid_t) -1) {
            logfile(LOG_ERR, "Unable to background: [fork: %s] #2",
                    strerror(errno));
            return;
        } else if ( child != (pid_t) 0) {
            _exit(EXIT_SUCCESS);       /* parent exits */
        }

        if (chdir("/") == -1) {
            logfile(LOG_ERR, "Unable to chdir: %s",
                    strerror(errno));
            return;
	}

        i = open_max();
        do {
            if (isatty((int) i)) {
                (void) close((int) i);
            }
            i--;
        } while (i > 2U);
        if (closedesc_all(1) != 0) {
            logfile(LOG_ERR,
                    "Unable to detach: /dev/null can't be duplicated");
            _exit(EXIT_FAILURE);
        }
    }
}

