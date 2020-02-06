EXECUTABLES = clibcrypt

all: $(EXECUTABLES)

ifdef OPENCL_INC
  CL_CFLAGS = -I$(OPENCL_INC)
endif

ifdef OPENCL_LIB
  CL_LDFLAGS = -L$(OPENCL_LIB)
endif

clibcrypt: bcrypt.c helper.c main.c 
	gcc $(CL_CFLAGS) $(CL_LDFLAGS) -std=gnu99 -o$@ $^ -lrt -lOpenCL -lbsd
	
clean:
	rm -f $(EXECUTABLES) *.o