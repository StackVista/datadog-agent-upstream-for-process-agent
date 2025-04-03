#ifndef __SQL_HELPERS_H
#define __SQL_HELPERS_H

#include "bpf_builtins.h"

#include "protocols/sql/defs.h"

// Check that we can read the amount of memory we want, then to the comparison.
// Note: we use `sizeof(command) - 1` to *not* compare with the null-terminator of
// the strings.
#define check_command(buf, command, buf_size) \
    (!bpf_memcmp((buf), &(command), sizeof(command) - 1))

// is_sql_command check that there is an SQL command in buf. We only check the
// most commonly used SQL command. We can find an SQL command both in the 'Q' message and in the 'C' one.
//
// Example Query message:
// 'Q'
// [int32 length = (length of SQL string + 4 bytes for length field)]
// "SELECT * FROM mytable;" 0
//
// Example Complete message:
// 'C'
// [int32 length]
// "SELECT 3" 0
static __always_inline bool is_sql_command(const char *buf, __u32 buf_size) {
    char tmp[SQL_COMMAND_MAX_SIZE];

    // Convert what would be the query to uppercase to match queries like
    // 'select * from table'
#pragma unroll (SQL_COMMAND_MAX_SIZE)
    for (int i = 0; i < SQL_COMMAND_MAX_SIZE; i++) {
        if ('a' <= buf[i] && buf[i] <= 'z') {
            tmp[i] = buf[i] - 'a' +'A';
        } else {
            tmp[i] = buf[i];
        }
    }

    return check_command(tmp, SQL_ALTER, buf_size)
        || check_command(tmp, SQL_CREATE, buf_size)
        || check_command(tmp, SQL_DELETE, buf_size)
        || check_command(tmp, SQL_DROP, buf_size)
        || check_command(tmp, SQL_INSERT, buf_size)
        || check_command(tmp, SQL_SELECT, buf_size)
        || check_command(tmp, SQL_UPDATE, buf_size);
}

#endif // __SQL_HELPERS_H
