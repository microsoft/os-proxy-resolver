/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/*
 * Error-capture shim around pacparser's error printer. pacparser reports
 * errors through a printf-style callback taking a va_list, which Rust cannot
 * receive on stable — so the callback lives here and Rust reads the buffer.
 *
 * A static buffer is safe because the crate serializes every pacparser call
 * on one dedicated worker thread.
 */
#include <stdarg.h>
#include <stdio.h>

typedef int (*pacparser_error_printer)(const char *fmt, va_list argp);
extern void pacparser_set_error_printer(pacparser_error_printer func);

static char ospr_err_buf[4096];
static size_t ospr_err_len = 0;

static int ospr_buf_printer(const char *fmt, va_list argp) {
  size_t remaining = sizeof(ospr_err_buf) - ospr_err_len;
  if (remaining > 1) {
    int n = vsnprintf(ospr_err_buf + ospr_err_len, remaining, fmt, argp);
    if (n > 0)
      ospr_err_len += ((size_t)n < remaining ? (size_t)n : remaining - 1);
  }
  return 0;
}

void ospr_install_error_printer(void) {
  pacparser_set_error_printer(ospr_buf_printer);
}

const char *ospr_get_error(void) { return ospr_err_buf; }

void ospr_clear_error(void) {
  ospr_err_len = 0;
  ospr_err_buf[0] = '\0';
}
