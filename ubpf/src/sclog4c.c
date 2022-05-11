/* Copyright (C) 2014 Christian Hujer.
 * All rights reserved.
 * Licensed under LGPLv3.
 * See file LICENSE in the root directory of this project.
 */

#include "inc/sclog4c.h"

int sclog4c_level = SL4C_WARNING;

static const struct sclog4c_messages {
  int level;
  const char *message;
} sclog4c_messages[] = {
        { SL4C_FATAL,    "fatal" },
        { SL4C_SEVERE,   "severe" },
        { SL4C_ERROR,    "error" },
        { SL4C_WARNING,  "warning" },
        { SL4C_INFO,     "info" },
        { SL4C_CONFIG,   "config" },
        { SL4C_DEBUG,    "debug" },
        { SL4C_FINE,     "fine" },
        { SL4C_FINER,    "finer" },
        { SL4C_FINEST,   "finest" },
};

const char *describe(int level)
{
    size_t i;
    for (i = 0; i < sizeof(sclog4c_messages) / sizeof(sclog4c_messages[0]); i++)
        if (level >= sclog4c_messages[i].level)
            return sclog4c_messages[i].message;
    return "all";
}