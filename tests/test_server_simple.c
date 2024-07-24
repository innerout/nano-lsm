#include <../lib/include/parallax/parallax.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	//PAR_OPEN TEST
	par_db_options *db_options = malloc(sizeof(par_db_options));
	db_options->options = malloc(sizeof(struct par_options_desc));

	db_options->create_flag = PAR_CREATE_DB;
	db_options->db_name = "database";
	db_options->options->value = 90909;
	db_options->volume_name = "~/db";

	par_handle handle = par_open(db_options, NULL);
	(void)handle;

	//PAR_PUT TEST
	struct par_key_value *kv = malloc(sizeof(struct par_key_value));
	uint64_t handle_val = 32;

	kv->k.data = "Sample put key";
	kv->k.size = 15;

	kv->v.val_buffer = "Sample put value";
	kv->v.val_buffer_size = 17;
	kv->v.val_size = 17;

	struct par_put_metadata metadata = par_put(&handle_val, kv, NULL);
	(void)metadata;

	//PAR_DELETE TEST
	struct par_key *k = malloc(sizeof(struct par_key));
	handle_val = 32;

	k->size = 15;
	k->data = "Sample put key";

	par_delete(&handle_val, k, NULL);

	return 0;
}
