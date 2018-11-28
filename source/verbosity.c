#include <stdio.h>
#include <stdarg.h>

extern int verbosity_user;


#define couleur(param) printf("\033[%sm",param)

void V_printf(int verbosity_program,char *color ,char *fmt, ...){
  if(verbosity_user >= verbosity_program){

    couleur(color);
    va_list ap;
    va_start(ap, fmt);
	  vfprintf(stdout, fmt, ap);
    va_end(ap);
    couleur("0");

  }
}

int getverbosity(){
  return verbosity_user; 

}
