# unset install to ignore rules being added by deps
#macro (install)
#endmacro ()

add_subdirectory(libsnark EXCLUDE_FROM_ALL)

# restore install
#macro (install)
#  _install(${ARGV})
#endmacro(install)
