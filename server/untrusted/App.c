/* App.c
*
* Copyright (C) 2006-2016 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/


#include "stdafx.h"
#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
// #include "client-tls.h"
#include "server-tls.h"

/* Use Debug SGX ? */
#if _DEBUG
	#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
	#define DEBUG_VALUE 1
#endif

int main(int argc, char* argv[]) /* not using since just testing w/ wc_test */
{
	sgx_enclave_id_t id;
	sgx_launch_token_t t;

	int ret = 0;
	int sgxStatus = 0;
	int updated = 0;

	/* only print off if no command line arguments were passed in */
	if (argc != 2 || strlen(argv[1]) != 2) {
		printf("Usage:\n"
               "\t-c Run a TLS client in enclave\n"
               "\t-s Run a TLS server in enclave\n"
               );
        return 0;
	}

    memset(t, 0, sizeof(sgx_launch_token_t));

	ret = sgx_create_enclave(SERVER_ENCLAVE_FILENAME, DEBUG_VALUE, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
		return 1;
	}


    switch(argv[1][1]) {
        // case 'c':
        //     printf("Client Test:\n");
        //     client_connect(id);
        //     break;

        case 's':
            printf("Server Test:\n");
            server_connect(id);
            break;

        default:
            printf("Unrecognized option set!\n");
            break;
    }

    return 0;
}
