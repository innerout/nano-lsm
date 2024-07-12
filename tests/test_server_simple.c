#include <../lib/include/parallax/parallax.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	//PAR_OPEN TEST
	par_db_options *db_options = malloc(sizeof(par_db_options));
	db_options->options = malloc(sizeof(struct par_options_desc));

	db_options->create_flag = PAR_CREATE_DB;
	db_options->db_name = "My sample database";
	db_options->options->value = 123456;
	db_options->volume_name = "Sample/Volume/name";

	par_open(db_options, NULL);

	//PAR_PUT TEST
	struct par_key_value *kv = malloc(sizeof(struct par_key_value));
	uint64_t handle_val = 32;

	kv->k.data = "Sample put key";
	kv->k.size = 15;

	kv->v.val_buffer = "Sample put value";
	kv->v.val_buffer_size = 17;
	kv->v.val_size = 17;

	par_put(&handle_val, kv, NULL);

	return 0;
}
