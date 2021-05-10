#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#define BUFFER_SIZE 256

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	FILE *f_plain;
	FILE *f_cipher;
	FILE *f_key;
	char plaintext[BUFFER_SIZE] = {0,};
	char ciphertext[BUFFER_SIZE] = {0,};
	char keytext[BUFFER_SIZE] = {0,};
	char file_name[BUFFER_SIZE] = "key_";
	int len=BUFFER_SIZE;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);


	if(strcmp(argv[1], "-e")==0)
	{
		printf("========================Encryption========================\n");
 
    		if ((f_plain = fopen(argv[2], "r+")) != NULL) {
        		memset(plaintext, 0, sizeof(plaintext));
        		fgets(plaintext, sizeof(plaintext), f_plain);
        		fclose(f_plain);
    		}
		else
		{	
			printf("error");			
			return 0;
		}
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		
		f_cipher = fopen(argv[2], "w");
        	fputs(ciphertext, f_cipher);
        	fclose(f_cipher);

		strcat(file_name, argv[2]);
		f_key = fopen(file_name, "w");
		sprintf(keytext, "%d", op.params[1].value.a);
        	fputs(keytext, f_key);
        	fclose(f_key);

		printf("Ciphertext : %s\n", ciphertext);
	}
	else if(strcmp(argv[1], "-d")==0)
	{
		printf("========================Decryption========================\n");
		if ((f_cipher = fopen(argv[2], "r+")) != NULL) {
        		memset(ciphertext, 0, sizeof(ciphertext));
        		fgets(ciphertext, sizeof(ciphertext), f_cipher);
        		fclose(f_cipher);
    		}
		else
		{	
			printf("error");			
			return 0;
		}

		if ((f_key = fopen(argv[3], "r+")) != NULL) {
        		memset(keytext, 0, sizeof(keytext));
        		fgets(keytext, sizeof(keytext), f_key);
        		fclose(f_key);
    		}
		else
		{	
			printf("error");			
			return 0;
		}
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		op.params[1].tmpref.buffer = keytext;
		op.params[1].tmpref.size = len;
		op.params[1].value.a = atoi(keytext);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		f_plain = fopen(argv[2], "w"); 
        	fputs(plaintext, f_plain);
        	fclose(f_plain);
		printf("Plaintext : %s\n", plaintext);

	}
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
