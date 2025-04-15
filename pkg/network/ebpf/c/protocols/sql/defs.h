#ifndef __SQL_DEFS_H
#define __SQL_DEFS_H

#define SQL_COMMAND_MAX_SIZE 6

// We miss at least:
// - SHOW
// - TRUNCATE
// But probably we don't want them to avoid increasing the complexity.
#define SQL_ALTER "ALTER"
#define SQL_CREATE "CREATE"
#define SQL_DELETE "DELETE"
#define SQL_DROP "DROP"
#define SQL_INSERT "INSERT"
#define SQL_SELECT "SELECT"
#define SQL_UPDATE "UPDATE"

#endif /*__SQL_DEFS_H*/
