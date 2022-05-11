/* Copyright (C) 2014 - 2015 Christian Hujer.
 * All rights reserved.
 * Licensed under LGPLv3.
 * See file LICENSE in the root directory of this project.
 */

#ifndef SCLOG4C_H
#define SCLOG4C_H

#include <limits.h>
#include <stdio.h>

/** The predefined log levels. */
enum LogLevel {
  SL4C_ALL = INT_MIN,
  SL4C_FINEST = 300,
  SL4C_FINER = 400,
  SL4C_FINE = 500,
  SL4C_DEBUG = 600,
  SL4C_CONFIG = 700,
  SL4C_INFO = 800,
  SL4C_WARNING = 900,
  SL4C_ERROR = 950,
  SL4C_SEVERE = 1000,
  SL4C_FATAL = 1100,
  SL4C_OFF = INT_MAX
};

#if !defined(SCLOG4C_LEVEL) || defined(_doxygen)
/** The global log level for compile-time log decision. */
#define SCLOG4C_LEVEL SL4C_ALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** The global log level. */
extern int sclog4c_level;

/** Returns a textual description of the specified @p level.
 * @param level
 *      Level for which to return a textual description.
 * @return String describing @p level.
 */
extern const char *describe(int level);

/** Prints a formatted log message to stderr.
 * @param level
 *      Level for which the log message is to be generated.
 *      Note this should not be an expression with side effects because the macro might evaluate this more than once.
 * @param fmt
 *      Format string for the log message.
 *      This must be a string literal.
 * @param ...
 *      Format arguments.
 */
#if defined(_doxygen) || defined(__GNUC__) || defined(__CC_ARM)
#define logm(level, fmt, ...) \
    if (level >= SCLOG4C_LEVEL) do { \
        if (level >= sclog4c_level) \
            fprintf(stderr, "%s:%d: %s: In function %s: " fmt "\n", __FILE__, __LINE__, describe(level), __func__, ##__VA_ARGS__); \
    } while (0)
#elif defined(__MSC_VER) && (__MSC_VER >= 1400)
#define logm(level, fmt, ...) \
    if (level >= SCLOG4C_LEVEL) do { \
        if (level >= sclog4c_level) \
            fprintf(stderr, "%s:%d: %s: In function %s: " fmt "\n", __FILE__, __LINE__, describe(level), __FUNCTION__, __VA_ARGS__); \
    } while (0)
#elif (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L))
#define logm(level, ...) \
    if (level >= SCLOG4C_LEVEL) do { \
        if (level >= sclog4c_level) { \
            fprintf(stderr, "%s:%d: %s: In function %s: ", __FILE__, __LINE__, describe(level), __func__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n"); \
        } \
    } while (0)
#else
#define logm(level, ...) \
    if (level >= SCLOG4C_LEVEL) do { \
        if (level >= sclog4c_level) { \
            fprintf(stderr, "%s:%d: %s: ", __FILE__, __LINE__, describe(level)); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n"); \
        } \
    } while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif
