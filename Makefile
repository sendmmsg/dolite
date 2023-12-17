all: 
	gcc -I../sqlite-autoconf-3440200 -L../sqlite-autoconf-3440200/.libs/ \
	-DPACKAGE_NAME="sqlite" \
	-DPACKAGE_TARNAME="sqlite" \
	-DPACKAGE_VERSION="3.44.2" \
	-DPACKAGE_STRING="sqlite\ 3.44.2" \
	-DPACKAGE_BUGREPORT="http://www.sqlite.org" \
	-DPACKAGE_URL="" \
	-DPACKAGE="sqlite" \
	-DVERSION="3.44.2" \
	-DHAVE_STDIO_H=1 \
	-DHAVE_STDLIB_H=1 \
	-DHAVE_STRING_H=1 \
	-DHAVE_INTTYPES_H=1 \
	-DHAVE_STDINT_H=1 \
	-DHAVE_STRINGS_H=1\
	-DHAVE_SYS_STAT_H=1 \
	-DHAVE_SYS_TYPES_H=1 \
	-DHAVE_UNISTD_H=1 \
	-DSTDC_HEADERS=1 \
	-DHAVE_DLFCN_H=1\
	-DHAVE_FDATASYNC=1 \
	-DHAVE_USLEEP=1 \
	-DHAVE_LOCALTIME_R=1 \
	-DHAVE_GMTIME_R=1 \
	-DHAVE_DECL_STRERROR_R=1 \
	-DHAVE_STRERROR_R=1 \
	-DHAVE_EDITLINE_READLINE_H=1 \
	-DHAVE_EDITLINE=1 \
	-DHAVE_POSIX_FALLOCATE=1 \
	-DHAVE_ZLIB_H=1    \
	-D_REENTRANT=1 \
	-DSQLITE_THREADSAFE=1 \
	-DSQLITE_ENABLE_MATH_FUNCTIONS \
	-DSQLITE_ENABLE_FTS4 \
	-DSQLITE_ENABLE_FTS5 \
	-DSQLITE_ENABLE_RTREE \
	-DSQLITE_ENABLE_GEOPOLY \
	-DSQLITE_ENABLE_SESSION \
	-DSQLITE_ENABLE_PREUPDATE_HOOK \
	-DSQLITE_HAVE_ZLIB  \
	-DSQLITE_ENABLE_EXPLAIN_COMMENTS \
	-DSQLITE_DQS=0 \
	-DSQLITE_ENABLE_DBPAGE_VTAB \
	-DSQLITE_ENABLE_STMTVTAB \
	-DSQLITE_ENABLE_DBSTAT_VTA \
	dolite.c dbhash.c ../sqlite-autoconf-3440200/.libs/libsqlite3.a  -o dolite -g -lm -lsodium
