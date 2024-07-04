#include <../lib/include/parallax/parallax.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	//PAR_PUT TEST
	struct par_key_value *kv = malloc(sizeof(struct par_key_value));
	uint64_t handle_val = 32;

	kv->k.data = "key";
	kv->k.size = 4;

	kv->v.val_buffer = "sample_value_data";
	kv->v.val_buffer_size = 18;
	kv->v.val_size = 18;

	par_put(&handle_val, kv, NULL);

	return 0;
}
