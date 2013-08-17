#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([src/Main/Utils.h])
AC_CONFIG_HEADERS([config.h])

PACKAGE=truecrack
VERSION=2.0
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)

# Checks for programs.
AC_PROG_CC([gcc cc])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h memory.h stddef.h stdlib.h string.h sys/mount.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset pow])

AC_CONFIG_FILES([Makefile
                 src/Makefile])


# Setup for MACOSX
#ifeq "$(shell uname -s)" "Darwin"
# ------------------------------------------------------------------------------
AC_CANONICAL_HOST    # needs to be called at some point earlier 
AM_CONDITIONAL([DARWIN], 
    [case $host_os in darwin*) true;; *) false;; esac]) 
    
# Setup CUDA paths
# ------------------------------------------------------------------------------
AC_ARG_WITH([cuda],
   [  --with-cuda=PATH                      prefix where cuda is installed [default=auto]])
if test -n "$with_cuda"
then
   CUDA_CFLAGS="-I$with_cuda/include"
   CUDA_LIBS="-L$with_cuda/lib"
   CUDA_LDFLAGS="-L$with_cuda/lib"
   NVCC="$with_cuda/bin/nvcc"
else
   CUDA_CFLAGS="-I/usr/local/cuda/include"
   CUDA_LIBS="-L/usr/local/cuda/lib"
   CUDA_LDFLAGS="-L/usr/local/cuda/lib"
   NVCC="nvcc"
fi
AC_ARG_ENABLE([debug],
             [  --enable-debug               enable nVidia CUDA debug mode [default=no]],
              [NVCCFLAGS="-G"],
              [NVCCFLAGS=""]
              )



AC_SUBST(CUDA_CFLAGS)
AC_SUBST(CUDA_LIBS)
AC_SUBST(NVCC)
AC_SUBST(NVCCFLAGS)

#Check for CUDA libraries
save_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS $CUDA_LDFLAGS"
AC_CHECK_LIB([cudart], [cudaMalloc])
LDFLAGS="$save_LDFLAGS"


# set the enable / disable of CUDA
AC_ARG_ENABLE([cpu],
	      [  --enable-cpu		Disable cuda nvidia GPU and use CPU [default=no]],
	      [enable_cpu="$enableval"],
	      [enable_cpu="no"]
	      )
AM_CONDITIONAL(ENABLE_CPU, test "$enable_cpu" = yes)


AC_OUTPUT
