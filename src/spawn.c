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
#include "spawn.h"
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

int spawn_handler(const int dev_desc_fd, const char * const script)
{
    pid_t pid;

    if (script == NULL || *script == 0) {
        return 0;
    }
    pid = fork();
    if (pid == (pid_t) 0) {
        (void) close(dev_desc_fd);
        execl(script, script, interface, vaddr_arg, xparam, (char *) NULL);
        logfile(LOG_ERR, "Unable to exec %s %s %s%s%s: %s",
                script, interface, vaddr_arg,
                (xparam ? " " : ""), (xparam ? xparam : ""),
                strerror(errno));
        _exit(EXIT_FAILURE);
    } else if (pid != (pid_t) -1) {
        logfile(LOG_WARNING, "Spawning [%s %s %s%s%s]",
                script, interface, vaddr_arg,
                (xparam ? " " : ""), (xparam ? xparam : ""));
#ifdef HAVE_WAITPID
        {
            while (waitpid(pid, NULL, 0) == (pid_t) -1 && errno == EINTR);
        }
#else
        {
            pid_t foundpid;

            do {
                foundpid = wait3(NULL, 0, NULL);
                if (foundpid == (pid_t) -1 && errno == EINTR) {
                    continue;
                }
            } while (foundpid != (pid_t) -1 && foundpid != pid);
        }
#endif
    } else {
        logfile(LOG_ERR, "Unable to spawn the script: %s",
                strerror(errno));
        return -1;
    }
    return 0;
}
