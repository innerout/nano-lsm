#include "serializer.h"

void par_append_data(void *dest, size_t *dest_len, const void *src, size_t src_len)
{
	memcpy((char *)dest + *dest_len, src, src_len);
	*dest_len += src_len;
}

char *par_serialize_par_db_options(par_db_options *db_options, size_t *ser_len)
{
	if (db_options == NULL)
		return NULL;

	size_t buffer_len = 0;

	buffer_len += sizeof(size_t);
	buffer_len += sizeof(size_t);
	buffer_len += strlen(db_options->db_name) + 1;
	buffer_len += strlen(db_options->volume_name) + 1;
	buffer_len += sizeof(db_options->create_flag);
	buffer_len += sizeof(db_options->options->value);

	size_t db_len = strlen(db_options->db_name) + 1;
	size_t volume_len = strlen(db_options->volume_name) + 1;

	char *ser = (char *)malloc(buffer_len);

	if (!ser)
		return NULL;

	char *ser_ptr = ser;

	memcpy(ser_ptr, &db_len, sizeof(size_t));
	ser_ptr += sizeof(size_t);

	memcpy(ser_ptr, &volume_len, sizeof(size_t));
	ser_ptr += sizeof(size_t);

	memcpy(ser_ptr, db_options->db_name, strlen(db_options->db_name) + 1);
	ser_ptr += strlen(db_options->db_name) + 1;

	memcpy(ser_ptr, db_options->volume_name, strlen(db_options->volume_name) + 1);
	ser_ptr += strlen(db_options->volume_name) + 1;

	memcpy(ser_ptr, &db_options->create_flag, sizeof(db_options->create_flag));
	ser_ptr += sizeof(db_options->create_flag);

	memcpy(ser_ptr, &db_options->options->value, sizeof(db_options->options->value));
	ser_ptr += sizeof(db_options->options->value);

	*ser_len += buffer_len;
	return ser;
}

char *par_serialize_command(uint32_t command, size_t *ser_len)
{
	size_t len = sizeof(uint32_t);
	char *ser = (char *)malloc(len);

	if (ser == NULL)
		return NULL;

	memcpy(ser, &command, len);

	*ser_len = len;
	return ser;
}

char *par_serialize_par_key(struct par_key *key, size_t *ser_len)
{
	if (key == NULL)
		return NULL;

	size_t buffer_len = 0;

	buffer_len += sizeof(uint32_t);
	buffer_len += strlen(key->data) + 1;
	printf("key buffer len is = %d\n", buffer_len);

	char *ser = (char *)malloc(buffer_len);

	if (!ser)
		return NULL;

	char *ser_ptr = ser;

	memcpy(ser_ptr, &(key->size), sizeof(uint32_t));
	ser_ptr += sizeof(uint32_t);

	memcpy(ser_ptr, key->data, strlen(key->data) + 1);
	ser_ptr += strlen(key->data) + 1;

	*ser_len += buffer_len;
	return ser;
}

char *par_serialize_par_value(struct par_value *value, size_t *ser_len)
{
	if (value == NULL)
		return NULL;

	size_t buffer_len = 0;

	buffer_len += sizeof(uint32_t);
	buffer_len += sizeof(uint32_t);
	buffer_len += strlen(value->val_buffer) + 1;

	char *ser = (char *)malloc(buffer_len);

	if (!ser)
		return NULL;

	char *ser_ptr = ser;

	memcpy(ser_ptr, &(value->val_buffer_size), sizeof(uint32_t));
	ser_ptr += sizeof(uint32_t);

	memcpy(ser_ptr, &(value->val_size), sizeof(uint32_t));
	ser_ptr += sizeof(uint32_t);

	memcpy(ser_ptr, value->val_buffer, strlen(value->val_buffer) + 1);
	ser_ptr += strlen(value->val_buffer) + 1;

	*ser_len += buffer_len;
	return ser;
}

char *par_serialize_handle(par_handle handle, size_t *ser_len)
{
	if (handle == NULL)
		return NULL;

	uint64_t value = *(uint64_t *)handle;
	char *ser = (char *)malloc(sizeof(uint64_t));

	char *ser_ptr = ser;

	memcpy(ser_ptr, &value, sizeof(uint64_t));
	ser_ptr += sizeof(uint64_t);

	*ser_len += sizeof(uint64_t);

	return ser;
}
