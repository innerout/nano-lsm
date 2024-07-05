#include "par_put.h"

void par_put_init(struct par_put_class *obj, par_handle handle, struct par_key_value *kv)
{
	obj->handle = handle;
	obj->kv = kv;
	obj->error_message = NULL;

	return;
}

void par_put_serialize(struct par_put_class *obj)
{
	char *par_message;
	char *par_command_message;
	char *par_handle_message;
	char *par_key_message;
	char *par_value_message;

	size_t key_len, value_len, par_handle_len, command_len = 0;

	par_command_message = par_serialize_command(1, &command_len);
	par_handle_message = par_serialize_handle(obj->handle, &par_handle_len);
	par_key_message = par_serialize_par_key(&obj->kv->k, &key_len);
	par_value_message = par_serialize_par_value(&obj->kv->v, &value_len);

	obj->stream_len = par_handle_len + command_len + key_len + value_len;
	par_message = malloc(obj->stream_len);

	size_t current_len = 0;
	par_append_data(par_message, &current_len, par_command_message, command_len);
	par_append_data(par_message, &current_len, par_handle_message, par_handle_len);
	par_append_data(par_message, &current_len, par_key_message, key_len);
	par_append_data(par_message, &current_len, par_value_message, value_len);

	obj->stream = par_message;
}

void par_put_send(struct par_put_class *obj)
{
	//For now it just does the deserialization without involving the network
	par_des_init(obj->stream, obj->stream_len);
}
