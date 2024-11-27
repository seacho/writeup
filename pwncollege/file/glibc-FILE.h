/* use in IDA to analyse libc.so version : 2.31*/

/* Type of MEMBER in struct type TYPE.  */
#define _IO_MEMBER_TYPE(TYPE, MEMBER) __typeof__ (((TYPE){}).MEMBER)

/* Essentially ((TYPE *) THIS)->MEMBER, but avoiding the aliasing
   violation in case THIS has a different pointer type.  */
#define _IO_CAST_FIELD_ACCESS(THIS, TYPE, MEMBER) \
  (*(_IO_MEMBER_TYPE (TYPE, MEMBER) *)(((char *) (THIS)) \
				       + offsetof(TYPE, MEMBER)))

#define _IO_JUMPS(THIS) (THIS)->vtable
#define _IO_JUMPS_FILE_plus(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
#define _IO_CHECK_WIDE(THIS) \
  (_IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data) != NULL)

#if _IO_JUMPS_OFFSET
# define _IO_JUMPS_FUNC(THIS) \
  (IO_validate_vtable                                                   \
   (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)	\
			     + (THIS)->_vtable_offset)))
# define _IO_JUMPS_FUNC_UPDATE(THIS, VTABLE)				\
  (*(const struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)	\
				  + (THIS)->_vtable_offset) = (VTABLE))
# define _IO_vtable_offset(THIS) (THIS)->_vtable_offset
#else
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
# define _IO_JUMPS_FUNC_UPDATE(THIS, VTABLE) \
  (_IO_JUMPS_FILE_plus (THIS) = (VTABLE))
# define _IO_vtable_offset(THIS) 0
#endif
#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
#define JUMP0(FUNC, THIS) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS)
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
#define JUMP3(FUNC, THIS, X1,X2,X3) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1,X2, X3)
#define JUMP_INIT(NAME, VALUE) VALUE
#define JUMP_INIT_DUMMY JUMP_INIT(dummy, 0), JUMP_INIT (dummy2, 0)

#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)
#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
#define WJUMP2(FUNC, THIS, X1, X2) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
#define WJUMP3(FUNC, THIS, X1,X2,X3) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1,X2, X3)

/* The 'finish' function does any final cleaning up of an _IO_FILE object.
   It does not delete (free) it, but does everything else to finalize it.
   It matches the streambuf::~streambuf virtual destructor.  */
typedef void (*_IO_finish_t) (FILE *, int); /* finalize */
#define _IO_FINISH(FP) JUMP1 (__finish, FP, 0)
#define _IO_WFINISH(FP) WJUMP1 (__finish, FP, 0)

/* The 'overflow' hook flushes the buffer.
   The second argument is a character, or EOF.
   It matches the streambuf::overflow virtual function. */
typedef int (*_IO_overflow_t) (FILE *, int);
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)

/* The 'underflow' hook tries to fills the get buffer.
   It returns the next character (as an unsigned char) or EOF.  The next
   character remains in the get buffer, and the get position is not changed.
   It matches the streambuf::underflow virtual function. */
typedef int (*_IO_underflow_t) (FILE *);
#define _IO_UNDERFLOW(FP) JUMP0 (__underflow, FP)
#define _IO_WUNDERFLOW(FP) WJUMP0 (__underflow, FP)

/* The 'uflow' hook returns the next character in the input stream
   (cast to unsigned char), and increments the read position;
   EOF is returned on failure.
   It matches the streambuf::uflow virtual function, which is not in the
   cfront implementation, but was added to C++ by the ANSI/ISO committee. */
#define _IO_UFLOW(FP) JUMP0 (__uflow, FP)
#define _IO_WUFLOW(FP) WJUMP0 (__uflow, FP)

/* The 'pbackfail' hook handles backing up.
   It matches the streambuf::pbackfail virtual function. */
typedef int (*_IO_pbackfail_t) (FILE *, int);
#define _IO_PBACKFAIL(FP, CH) JUMP1 (__pbackfail, FP, CH)
#define _IO_WPBACKFAIL(FP, CH) WJUMP1 (__pbackfail, FP, CH)

/* The 'xsputn' hook writes upto N characters from buffer DATA.
   Returns EOF or the number of character actually written.
   It matches the streambuf::xsputn virtual function. */
typedef size_t (*_IO_xsputn_t) (FILE *FP, const void *DATA,
				    size_t N);
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
#define _IO_WXSPUTN(FP, DATA, N) WJUMP2 (__xsputn, FP, DATA, N)

/* The 'xsgetn' hook reads upto N characters into buffer DATA.
   Returns the number of character actually read.
   It matches the streambuf::xsgetn virtual function. */
typedef size_t (*_IO_xsgetn_t) (FILE *FP, void *DATA, size_t N);
#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)
#define _IO_WXSGETN(FP, DATA, N) WJUMP2 (__xsgetn, FP, DATA, N)

/* The 'seekoff' hook moves the stream position to a new position
   relative to the start of the file (if DIR==0), the current position
   (MODE==1), or the end of the file (MODE==2).
   It matches the streambuf::seekoff virtual function.
   It is also used for the ANSI fseek function. */
typedef off64_t (*_IO_seekoff_t) (FILE *FP, off64_t OFF, int DIR,
				      int MODE);
#define _IO_SEEKOFF(FP, OFF, DIR, MODE) JUMP3 (__seekoff, FP, OFF, DIR, MODE)
#define _IO_WSEEKOFF(FP, OFF, DIR, MODE) WJUMP3 (__seekoff, FP, OFF, DIR, MODE)

/* The 'seekpos' hook also moves the stream position,
   but to an absolute position given by a fpos64_t (seekpos).
   It matches the streambuf::seekpos virtual function.
   It is also used for the ANSI fgetpos and fsetpos functions.  */
/* The _IO_seek_cur and _IO_seek_end options are not allowed. */
typedef off64_t (*_IO_seekpos_t) (FILE *, off64_t, int);
#define _IO_SEEKPOS(FP, POS, FLAGS) JUMP2 (__seekpos, FP, POS, FLAGS)
#define _IO_WSEEKPOS(FP, POS, FLAGS) WJUMP2 (__seekpos, FP, POS, FLAGS)

/* The 'setbuf' hook gives a buffer to the file.
   It matches the streambuf::setbuf virtual function. */
typedef FILE* (*_IO_setbuf_t) (FILE *, char *, ssize_t);
#define _IO_SETBUF(FP, BUFFER, LENGTH) JUMP2 (__setbuf, FP, BUFFER, LENGTH)
#define _IO_WSETBUF(FP, BUFFER, LENGTH) WJUMP2 (__setbuf, FP, BUFFER, LENGTH)

/* The 'sync' hook attempts to synchronize the internal data structures
   of the file with the external state.
   It matches the streambuf::sync virtual function. */
typedef int (*_IO_sync_t) (FILE *);
#define _IO_SYNC(FP) JUMP0 (__sync, FP)
#define _IO_WSYNC(FP) WJUMP0 (__sync, FP)

/* The 'doallocate' hook is used to tell the file to allocate a buffer.
   It matches the streambuf::doallocate virtual function, which is not
   in the ANSI/ISO C++ standard, but is part traditional implementations. */
typedef int (*_IO_doallocate_t) (FILE *);
#define _IO_DOALLOCATE(FP) JUMP0 (__doallocate, FP)
#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)

/* The following four hooks (sysread, syswrite, sysclose, sysseek, and
   sysstat) are low-level hooks specific to this implementation.
   There is no correspondence in the ANSI/ISO C++ standard library.
   The hooks basically correspond to the Unix system functions
   (read, write, close, lseek, and stat) except that a FILE*
   parameter is used instead of an integer file descriptor;  the default
   implementation used for normal files just calls those functions.
   The advantage of overriding these functions instead of the higher-level
   ones (underflow, overflow etc) is that you can leave all the buffering
   higher-level functions.  */

/* The 'sysread' hook is used to read data from the external file into
   an existing buffer.  It generalizes the Unix read(2) function.
   It matches the streambuf::sys_read virtual function, which is
   specific to this implementation. */
typedef ssize_t (*_IO_read_t) (FILE *, void *, ssize_t);
#define _IO_SYSREAD(FP, DATA, LEN) JUMP2 (__read, FP, DATA, LEN)
#define _IO_WSYSREAD(FP, DATA, LEN) WJUMP2 (__read, FP, DATA, LEN)

/* The 'syswrite' hook is used to write data from an existing buffer
   to an external file.  It generalizes the Unix write(2) function.
   It matches the streambuf::sys_write virtual function, which is
   specific to this implementation. */
typedef ssize_t (*_IO_write_t) (FILE *, const void *, ssize_t);
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
#define _IO_WSYSWRITE(FP, DATA, LEN) WJUMP2 (__write, FP, DATA, LEN)

/* The 'sysseek' hook is used to re-position an external file.
   It generalizes the Unix lseek(2) function.
   It matches the streambuf::sys_seek virtual function, which is
   specific to this implementation. */
typedef off64_t (*_IO_seek_t) (FILE *, off64_t, int);
#define _IO_SYSSEEK(FP, OFFSET, MODE) JUMP2 (__seek, FP, OFFSET, MODE)
#define _IO_WSYSSEEK(FP, OFFSET, MODE) WJUMP2 (__seek, FP, OFFSET, MODE)

/* The 'sysclose' hook is used to finalize (close, finish up) an
   external file.  It generalizes the Unix close(2) function.
   It matches the streambuf::sys_close virtual function, which is
   specific to this implementation. */
typedef int (*_IO_close_t) (FILE *); /* finalize */
#define _IO_SYSCLOSE(FP) JUMP0 (__close, FP)
#define _IO_WSYSCLOSE(FP) WJUMP0 (__close, FP)

/* The 'sysstat' hook is used to get information about an external file
   into a struct stat buffer.  It generalizes the Unix fstat(2) call.
   It matches the streambuf::sys_stat virtual function, which is
   specific to this implementation. */
typedef int (*_IO_stat_t) (FILE *, void *);
#define _IO_SYSSTAT(FP, BUF) JUMP1 (__stat, FP, BUF)
#define _IO_WSYSSTAT(FP, BUF) WJUMP1 (__stat, FP, BUF)

/* The 'showmany' hook can be used to get an image how much input is
   available.  In many cases the answer will be 0 which means unknown
   but some cases one can provide real information.  */
typedef int (*_IO_showmanyc_t) (FILE *);
#define _IO_SHOWMANYC(FP) JUMP0 (__showmanyc, FP)
#define _IO_WSHOWMANYC(FP) WJUMP0 (__showmanyc, FP)

/* The 'imbue' hook is used to get information about the currently
   installed locales.  */
typedef void (*_IO_imbue_t) (FILE *, void *);
#define _IO_IMBUE(FP, LOCALE) JUMP1 (__imbue, FP, LOCALE)
#define _IO_WIMBUE(FP, LOCALE) WJUMP1 (__imbue, FP, LOCALE)


#define _IO_CHAR_TYPE char /* unsigned char ? */
#define _IO_INT_TYPE int

struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
struct _IO_FILE;

/* The opaque type of streams.  This is the definition used elsewhere.  */
typedef struct _IO_FILE FILE;
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};



#define __off_t long int
#define __off64_t		long int
typedef void _IO_lock_t;
struct _IO_marker {
  struct _IO_marker *_next;
  FILE *_sbuf;
  /* If _pos >= 0
 it points to _buf->Gbase()+_pos. FIXME comment */
  /* if _pos < 0, it points to _buf->eBptr()+_pos. FIXME comment */
  int _pos;
};
struct __gconv_step;
struct __gconv_step_data;
struct __gconv_loaded_object;


/* Type of a conversion function.  */
typedef int (*__gconv_fct) (struct __gconv_step *, struct __gconv_step_data *,
			    const unsigned char **, const unsigned char *,
			    unsigned char **, size_t *, int, int);

/* Type of a specialized conversion function for a single byte to INTERNAL.  */
typedef wint_t (*__gconv_btowc_fct) (struct __gconv_step *, unsigned char);

/* Constructor and destructor for local data for conversion step.  */
typedef int (*__gconv_init_fct) (struct __gconv_step *);
typedef void (*__gconv_end_fct) (struct __gconv_step *);

struct __gconv_loaded_object
{
  /* Name of the object.  It must be the first structure element.  */
  const char *name;

  /* Reference counter for the db functionality.  If no conversion is
     needed we unload the db library.  */
  int counter;

  /* The handle for the shared object.  */
  void *handle;

  /* Pointer to the functions the module defines.  */
  __gconv_fct fct;
  __gconv_init_fct init_fct;
  __gconv_end_fct end_fct;
};


struct __gconv_step
{
  struct __gconv_loaded_object *__shlib_handle;
  const char *__modname;

  /* For internal use by glibc.  (Accesses to this member must occur
     when the internal __gconv_lock mutex is acquired).  */
  int __counter;

  char *__from_name;
  char *__to_name;

  __gconv_fct __fct;
  __gconv_btowc_fct __btowc_fct;
  __gconv_init_fct __init_fct;
  __gconv_end_fct __end_fct;

  /* Information about the number of bytes needed or produced in this
     step.  This helps optimizing the buffer sizes.  */
  int __min_needed_from;
  int __max_needed_from;
  int __min_needed_to;
  int __max_needed_to;

  /* Flag whether this is a stateful encoding or not.  */
  int __stateful;

  void *__data;		/* Pointer to step-local data.  */
};

/* Additional data for steps in use of conversion descriptor.  This is
   allocated by the `init' function.  */
struct __gconv_step_data
{
  unsigned char *__outbuf;    /* Output buffer for this step.  */
  unsigned char *__outbufend; /* Address of first byte after the output
				 buffer.  */

  /* Is this the last module in the chain.  */
  int __flags;

  /* Counter for number of invocations of the module function for this
     descriptor.  */
  int __invocation_counter;

  /* Flag whether this is an internal use of the module (in the mb*towc*
     and wc*tomb* functions) or regular with iconv(3).  */
  int __internal_use;

  __mbstate_t *__statep;
  __mbstate_t __state;	/* This element must not be used directly by
			   any module; always use STATEP!  */
};


typedef struct
{
  struct __gconv_step *step;
  struct __gconv_step_data step_data;
} _IO_iconv_t;

struct _IO_codecvt
{
  _IO_iconv_t __cd_in;
  _IO_iconv_t __cd_out;
};

#ifndef __WINT_TYPE__
# define __WINT_TYPE__ unsigned int
#endif

/* Conversion state information.  */
typedef struct
{
  int __count;
  union
  {
    __WINT_TYPE__ __wch;
    char __wchb[4];
  } __value;		/* Value so far.  */
} __mbstate_t;

/* Extra data for wide character streams.  */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};



struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
// #ifdef _IO_USE_OLD_IO_FILE
// };

// struct _IO_FILE_complete
// {
//   struct _IO_FILE _file;
// #endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
