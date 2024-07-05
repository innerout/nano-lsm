#include "deserializer.h"

Par_deserialize par_deserialize[] = { par_des_open, par_des_put, par_des_get, par_des_error };

void par_des_init(char *par_stream, size_t message_len)
{
	log_debug("Initialization of deserialization\n");
	if (par_stream == NULL)
		return;

	par_deserialize[par_des_opcode(par_stream)](par_stream);
}

uint32_t par_des_opcode(char *par_stream)
{
	uint32_t opcode;
	memcpy(&opcode, par_stream, sizeof(uint32_t));

	if (opcode < 0 || opcode > MAX_OPCODE_NUM) {
		return MAX_OPCODE_NUM + 1;
	}

	return opcode;
}

void par_des_open(char *par_stream)
{
}

void par_des_put(char *par_stream)
{
	par_handle handle;
	struct par_key_value *kv = malloc(sizeof(struct par_key_value));

	//Skipping opcode
	par_stream += sizeof(uint32_t);

	//Deserializing handle
	memcpy(&handle, par_stream, sizeof(uint64_t));
	par_stream += sizeof(uint64_t);

	//Deserializing Key field
	memcpy(&(kv->k.size), par_stream, sizeof(uint32_t));
	par_stream += sizeof(uint32_t);

	char *key_data = malloc(kv->k.size);
	memcpy(key_data, par_stream, kv->k.size);
	par_stream += kv->k.size;
	kv->k.data = key_data;

	//Deserializing Value field
	memcpy(&(kv->v.val_size), par_stream, sizeof(uint32_t));
	par_stream += sizeof(uint32_t);

	memcpy(&(kv->v.val_buffer_size), par_stream, sizeof(uint32_t));
	par_stream += sizeof(uint32_t);

	kv->v.val_buffer = malloc(kv->v.val_buffer_size);
	memcpy(kv->v.val_buffer, par_stream, kv->v.val_buffer_size);
	par_stream += kv->v.val_buffer_size;

	//Call server's par_put function

	return;
}

void par_des_get(char *par_stream)
{
}

void par_des_error(char *par_stream)
{
	log_debug("Error, invalid opcode\n");
	return;
}
