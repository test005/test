#include "get_decryption_password.h"
#include "read_pass.h"

char* const get_decryption_password()
{
    return read_pass("Enter decryption password: ");
}

