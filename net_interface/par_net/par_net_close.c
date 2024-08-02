#include "par_net_close.h"
#include "par_net.h"

struct par_net_close_req {
    uint64_t region_id;
}__attribute__((packed));

struct par_net_close_rep {
    uint32_t status;
    uint32_t string_size;
    uint32_t total_bytes;
}__attribute__((packed));

uint32_t par_net_close_req_calc_size(void){
    return sizeof(struct par_net_close_req);
}

size_t par_net_close_rep_calc_size(uint32_t string_size){
    return sizeof(struct par_net_close_rep) + string_size;
}

struct par_net_close_req *par_net_close_req_create(uint64_t region_id, char *buffer, size_t *buffer_len){
    if(par_net_close_req_calc_size() > *buffer_len)
        return NULL;

    struct par_net_close_req *request = (struct par_net_close_req*)(buffer);
    request->region_id = region_id;

    return request;
}

uint64_t par_net_close_get_region_id(struct par_net_close_req *request){
    return request->region_id;
}

struct par_net_close_rep *par_net_close_rep_create(int status, const char* return_string, size_t *rep_len){

    uint32_t string_size;
    if(!return_string){
      string_size = 0;
    }else{
      string_size = strlen(return_string);
    }
    *rep_len = par_net_close_rep_calc_size(string_size);
    char *reply_buffer = malloc(*rep_len);
    
    struct par_net_close_rep *reply = (struct par_net_close_rep *)reply_buffer;
    
    reply->total_bytes = *rep_len;
    reply->status = status;
    if(status == 1)
        return reply;

    memcpy(&reply_buffer[sizeof(struct par_net_close_rep) + string_size], return_string, string_size);

    return reply;
}

const char* par_net_close_get_string(struct par_net_close_rep *reply){
    return (char*)reply + sizeof(struct par_net_close_req);
}

const char* par_net_close_rep_handle_reply(char* buffer){
    struct par_net_close_rep *reply = (struct par_net_close_rep*)buffer;
    
    if(reply->status == 1){
        log_fatal("Invalid reply status");
        const char* return_string = par_net_close_get_string(reply);
        return return_string;
    }
  
    return NULL;
}

