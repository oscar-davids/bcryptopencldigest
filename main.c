#include "timing.h"
#include "helper.h"
#include "bcrypt.h"

#define MEM_SIZE (128)
#define MAX_SOURCE_SIZE (0x100000)


#ifdef _WIN32
typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned __int64	u64;
#else
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define min(X,Y) ((X) < (Y) ? (X) : (Y))
#define max(X,Y) ((X) > (Y) ? (X) : (Y))

#endif // _WIN32


typedef struct pw
{
    u32 i[64];
    
    u32 pw_len;
    
    u32 alignment_placeholder_1;
    u32 alignment_placeholder_2;
    u32 alignment_placeholder_3;
    
} pw_t;


static const char PROGNAME[] = "clBcrypt";

int main(int argc, char **argv)
{
  //const int ntrips = argc >= 3 ? atoi(argv[2]) : DEFAULT_NTRIPS;
  //const cl_long n = argc >= 2 ? atol(argv[1]) : DEFAULT_N;

	u32 salt_u32[4], result[6], salt_tmp[4];
	u32 resultest[6];

	cl_mem bufferA = NULL;
    cl_mem bufferB = NULL;
    cl_mem bufferC = NULL;
    cl_mem bufferD = NULL;

	char temp[BCRYPT_HASHSIZE];
	char tempsalt[BCRYPT_HASHSIZE];	
	char encodesalt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	char pwd[MEM_SIZE] = "jianwei";	
	char salt[MEM_SIZE] = "$2a$10$0000000000000000000000";

	FILE* pinFile;
	FILE* poutFile;
	int i = 0;
	u32 workFactor = 10; //default
	u32 paramround = 1024;

	if (argc != 4 && argc != 5)
	{
		printf("invalid argument\n");
		printf("ex1. clBcrypt password salt round(2^n, 1024,2048)\n");
		printf("ex2. clBcrypt passsalt.txt out.txt round(2^n, 1024,2048)\n");
		return  0;
	}
	if (argc == 4) paramround = atoi(argv[3]);
	if (argc == 5) paramround = atoi(argv[4]);

	int j = 0;
	for ( j = 0; j < 50; j++)
	{
		if (paramround >> j == 0)
			break;
	}
	workFactor = j - 1;

	if (workFactor < 1 || workFactor > 50)
	{
		printf("invalid argument\n");
		return  0;
	}

	//predecide salt
	sprintf(tempsalt, "$2a$%02d$0000000000000000000000", workFactor);
	
	u32 loop_cnt = 1 << workFactor, *loop_cnt_ptr = &loop_cnt;
    pw_t pw, *pws = &pw;

	//pw_t salt, *psalt = &salt;
    
    
    //bcrypt_gensalt(workFactor, salt);
    
  cl_context ctx;
  cl_command_queue queue;
  create_context_on(CHOOSE_INTERACTIVELY, CHOOSE_INTERACTIVELY, 0, &ctx, &queue, 0);

  //print_device_info_from_queue(queue);

  // --------------------------------------------------------------------------
  // load kernels 
  // --------------------------------------------------------------------------
  char *knl_text = read_file("cpyptcore.cl");
  cl_kernel knl = kernel_from_string(ctx, knl_text, "mybcrypt", NULL);
  free(knl_text);

  // --------------------------------------------------------------------------
  // allocate device memory
  // --------------------------------------------------------------------------
  cl_int status;
  bufferA = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 
      1 * sizeof(pw_t), 0, &status);
  CHECK_CL_ERROR(status, "clCreateBuffer");

  bufferB = clCreateBuffer(ctx, CL_MEM_READ_WRITE,
      4 * sizeof(u32), 0, &status);
  CHECK_CL_ERROR(status, "clCreateBuffer");

  bufferC = clCreateBuffer(ctx, CL_MEM_READ_WRITE,
      1 * sizeof(u32), 0, &status);
  CHECK_CL_ERROR(status, "clCreateBuffer");
  
  bufferD = clCreateBuffer(ctx, CL_MEM_READ_WRITE,
      6 * sizeof(u32), 0, &status);
  CHECK_CL_ERROR(status, "clCreateBuffer");
   
   
  // --------------------------------------------------------------------------
  // run code on device
  // --------------------------------------------------------------------------
	if (argc == 5)
	{
		if (strcmp(argv[1], "-l") == 0)
		{
			printf("infile %s\n", argv[2]);
			pinFile = fopen(argv[2], "r");
			if (pinFile == 0)
			{
				printf("can not input file\n");		
				return 0;
			}
			//assert(pinFile != 0);

			printf("outfile %s\n", argv[3]);
			poutFile = fopen(argv[3], "w+");
			if (poutFile == 0)
			{
				printf("can not out file\n");
				return 0;
			}
			//assert(poutFile != 0);

			while (fscanf(pinFile, "%s %s", pwd, temp) == 2)
			{

				strcpy(encodesalt, temp);
				int nlen = min(strlen(encodesalt), 16);

				u32 encsalt[4];

				char *pstr = encodesalt;
				for (int i = 0; i < 4; i++) {
					u32 tmp = 0;
					for (int j = 0; j < 4; j++) {
						tmp <<= 8;
						tmp |= (unsigned char)*pstr;
						if (!*pstr) {
							tmp <<= 8 * (3 - j);
							break;
						}
						else pstr++;
					}

					encsalt[i] = tmp;
					BF_swap(&encsalt[i], 1);
				}

				BF_encode(encodesalt, encsalt, 16);

				for (i = 0; i < 22; i++)
				{
					salt[7 + i] = encodesalt[i];
				}

				printf("pass: %s salt: %s \n", argv[1], salt);


				BF_decode(salt_u32, &salt[7], 16);
				BF_swap(salt_u32, 4);


				char *ptr = pwd;
				for (int i = 0; i < 18; i++) {
					u32 tmp = 0;
					for (int j = 0; j < 4; j++) {
						tmp <<= 8;
						tmp |= (unsigned char)*ptr;
						if (!*ptr) {
							tmp <<= 8 * (3 - j);
							break;
						}
						else ptr++;
					}

					pw.i[i] = tmp;
					BF_swap(&pw.i[i], 1);
				}
				pw.pw_len = strlen(pwd);

				// --------------------------------------------------------------------------
 // transfer to device
 // --------------------------------------------------------------------------
				CALL_CL_GUARDED(clEnqueueWriteBuffer, (
					queue, bufferA, /*blocking*/ CL_TRUE, /*offset*/ 0,
					1 * sizeof(pw_t), pws,
					0, NULL, NULL));

				CALL_CL_GUARDED(clEnqueueWriteBuffer, (
					queue, bufferB, /*blocking*/ CL_TRUE, /*offset*/ 0,
					4 * sizeof(u32), salt_u32,
					0, NULL, NULL));

				CALL_CL_GUARDED(clEnqueueWriteBuffer, (
					queue, bufferC, /*blocking*/ CL_TRUE, /*offset*/ 0,
					1 * sizeof(u32), loop_cnt_ptr,
					0, NULL, NULL));

				CALL_CL_GUARDED(clEnqueueWriteBuffer, (
					queue, bufferD, /*blocking*/ CL_TRUE, /*offset*/ 0,
					6 * sizeof(u32), result,
					0, NULL, NULL));
///

				CALL_CL_GUARDED(clFinish, (queue));

				timestamp_type time1, time2;
				get_timestamp(&time1);

				SET_4_KERNEL_ARGS(knl, bufferA, bufferB, bufferC, bufferD);

				status = clEnqueueTask(queue, knl, 0, NULL, NULL);
				CHECK_CL_ERROR(status, "clCreateBuffer");

				CALL_CL_GUARDED(clFinish, (queue));

				get_timestamp(&time2);
				double elapsed = timestamp_diff_in_seconds(time1, time2);
				printf("%f s\n", elapsed);

				// --------------------------------------------------------------------------
				// transfer back & check
				// --------------------------------------------------------------------------

				CALL_CL_GUARDED(clEnqueueReadBuffer, (
					queue, bufferD, /*blocking*/ CL_TRUE, /*offset*/ 0,
					6 * sizeof(u32), resultest,
					0, NULL, NULL));

				memcpy(hash, salt, 7 + 22);
				BF_swap(resultest, 6);
				BF_encode(&hash[7 + 22], resultest, 23);
				hash[7 + 22 + 31] = '\0';

				fprintf(poutFile, "%s\n", hash);

				puts(hash);
			}

			fclose(pinFile);
			fclose(poutFile);
		}
	}
	else
	{
			if (argc == 4)
			{
				strcpy(pwd, argv[1]);
				strcpy(salt, tempsalt);

				strcpy(encodesalt, argv[2]);
				int nlen = min(strlen(encodesalt), 16);
				
				u32 encsalt[4];

				char *ptr = encodesalt;
				for (int i = 0; i < 4; i++) {
					u32 tmp = 0;
					for (int j = 0; j < 4; j++) {
						tmp <<= 8;
						tmp |= (unsigned char)*ptr;
						if (!*ptr) {
							tmp <<= 8 * (3 - j);
							break;
						}
						else ptr++;
					}

					encsalt[i] = tmp;
					BF_swap(&encsalt[i], 1);
				}
				
				BF_encode(encodesalt, encsalt, 16);

				for (i = 0; i < 22; i++)
				{
					salt[7 + i] = encodesalt[i];
				}				

				printf("pass: %s salt: %s \n", argv[1], salt);
			}

			BF_decode(salt_u32, &salt[7], 16);
			BF_swap(salt_u32, 4);
			char *ptr = pwd;
			for (int i = 0; i < 18; i++) {
				u32 tmp = 0;
				for (int j = 0; j < 4; j++) {
					tmp <<= 8;
					tmp |= (unsigned char)*ptr;
					if (!*ptr) {
						tmp <<= 8 * (3 - j);
						break;
					}
					else ptr++;
				}

				pw.i[i] = tmp;
				BF_swap(&pw.i[i], 1);
			}
			pw.pw_len = strlen(pwd);

			// transfer to device
 // --------------------------------------------------------------------------
			CALL_CL_GUARDED(clEnqueueWriteBuffer, (
				queue, bufferA, /*blocking*/ CL_TRUE, /*offset*/ 0,
				1 * sizeof(pw_t), pws,
				0, NULL, NULL));

			CALL_CL_GUARDED(clEnqueueWriteBuffer, (
				queue, bufferB, /*blocking*/ CL_TRUE, /*offset*/ 0,
				4 * sizeof(u32), salt_u32,
				0, NULL, NULL));

			CALL_CL_GUARDED(clEnqueueWriteBuffer, (
				queue, bufferC, /*blocking*/ CL_TRUE, /*offset*/ 0,
				1 * sizeof(u32), loop_cnt_ptr,
				0, NULL, NULL));

			CALL_CL_GUARDED(clEnqueueWriteBuffer, (
				queue, bufferD, /*blocking*/ CL_TRUE, /*offset*/ 0,
				6 * sizeof(u32), result,
				0, NULL, NULL));
			///

			CALL_CL_GUARDED(clFinish, (queue));

			timestamp_type time1, time2;
			get_timestamp(&time1);

			SET_4_KERNEL_ARGS(knl, bufferA, bufferB, bufferC, bufferD);

			status = clEnqueueTask(queue, knl, 0, NULL, NULL);
			CHECK_CL_ERROR(status, "clCreateBuffer");

			CALL_CL_GUARDED(clFinish, (queue));

			get_timestamp(&time2);
			double elapsed = timestamp_diff_in_seconds(time1, time2);
			printf("%f s\n", elapsed);

			// --------------------------------------------------------------------------
			// transfer back & check
			// --------------------------------------------------------------------------

			CALL_CL_GUARDED(clEnqueueReadBuffer, (
				queue, bufferD, /*blocking*/ CL_TRUE, /*offset*/ 0,
				6 * sizeof(u32), result,
				0, NULL, NULL));

			memcpy(hash, salt, 7 + 22);
			BF_swap(result, 6);
			BF_encode(&hash[7 + 22], result, 23);
			hash[7 + 22 + 31] = '\0';
			puts(hash);
	}

  // --------------------------------------------------------------------------
  // clean up
  // --------------------------------------------------------------------------
  CALL_CL_GUARDED(clReleaseMemObject, (bufferA));
  CALL_CL_GUARDED(clReleaseMemObject, (bufferB));
  CALL_CL_GUARDED(clReleaseMemObject, (bufferC));
  CALL_CL_GUARDED(clReleaseMemObject, (bufferD));
  CALL_CL_GUARDED(clReleaseKernel, (knl));
  CALL_CL_GUARDED(clReleaseCommandQueue, (queue));
  CALL_CL_GUARDED(clReleaseContext, (ctx));

  return 0;
}
