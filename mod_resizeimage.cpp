/* 
 * Copyright 2011 Toshiyuki Suzumura
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


extern "C" {
  #include <httpd/httpd.h>
  #include <httpd/http_protocol.h>
  #include <httpd/http_config.h>
  #include <httpd/http_request.h>
  #include <httpd/http_log.h>
  #include <httpd/ap_config.h>
  #include <httpd/ap_mpm.h>
  #include <apr_strings.h>
}
#include <Magick++.h>
#include <libmemcached/memcached.h>

#define AP_LOG_VERBOSE(rec, fmt, ...) //ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, "[resize] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[resize] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[resize] " fmt, ##__VA_ARGS__)

#define RESIZE   "X-ResizeImage"

static const char X_RESIZE[] = RESIZE;
static const char X_RESIZE_PARAM[] = RESIZE "-Param";
static const char X_RESIZE_HASH[]  = RESIZE "-Hash";
extern "C" module AP_MODULE_DECLARE_DATA resizeimage_module;

struct resize_conf {
  int       enabled;
  int       expire;
  int       jpeg_quality;
  memcached_st* memc;
};

//
// Utils.
//
static const char* get_and_unset_header(apr_table_t* tbl, const char* key)
{
  const char* value = apr_table_get(tbl, key);
  if(value) apr_table_unset(tbl, key);
  return value;
}
  

static void unset_header(request_rec* rec, const char* key)
{
  apr_table_unset(rec->headers_out, key);
  apr_table_unset(rec->err_headers_out, key);
}


//
// Output filter.
//
static apr_status_t resize_output_filter(ap_filter_t* f, apr_bucket_brigade* in_bb)
{
  request_rec* rec =f->r;
  resize_conf* conf = (resize_conf*)ap_get_module_config(rec->per_dir_config, &resizeimage_module);
  const char* content_type, *target_type = "JPEG";
  const char* image_url, *resize_param, *image_hash=NULL;
  Magick::Blob blob;
  char* vlob = NULL;
  size_t vlob_length = 0;
  int cache_hit = FALSE;

  AP_LOG_VERBOSE(rec, "Incoming %s.", __FUNCTION__);

  // Pass thru by request types.
  if(rec->status!=HTTP_OK || rec->main!=NULL || rec->header_only
    || (rec->handler!= NULL && strcmp(rec->handler, "default-handler") == 0)) goto PASS_THRU;

  AP_LOG_VERBOSE(rec, "-- Checking responce headers.");

  // Obtain and erase x-resize-image header or pass through.
  image_url = get_and_unset_header(rec->headers_out, X_RESIZE);
  if(image_url== NULL || image_url[0]=='\0') {
    image_url = get_and_unset_header(rec->err_headers_out, X_RESIZE);
  }
  if(image_url==NULL || image_url[0]=='\0') goto PASS_THRU;

  // Check content-type
  content_type = rec->content_type;
  if(content_type) {
    if(strcasecmp(content_type, "image/jpeg")==0) {
      target_type = "JPEG";
    } else
    if(strcasecmp(content_type, "image/png")==0) {
      target_type = "PNG";
    } else
    if(strcasecmp(content_type, "image/gif")==0) {
      target_type = "GIF";
    } else goto PASS_THRU;
  }

  // Resize parameter
  resize_param = get_and_unset_header(rec->headers_out, X_RESIZE_PARAM);
  if(resize_param==NULL || resize_param[0]=='\0') {
    resize_param = get_and_unset_header(rec->err_headers_out, X_RESIZE_PARAM);
  }
  if(resize_param[0]=='\0') resize_param = NULL;

  // Image hash
  image_hash = get_and_unset_header(rec->headers_out, X_RESIZE_HASH);
  if(image_hash==NULL || image_hash[0]=='\0') {
    image_hash = get_and_unset_header(rec->err_headers_out, X_RESIZE_HASH);
  }
 
  // Open image and resize.
  AP_LOG_INFO(rec, "URL: %s, %s => %s (%s)", image_url, content_type, resize_param, image_hash);

  if(image_hash) {
    // Try memcached...
    image_hash = apr_psprintf(rec->pool, "%s:%s:%s", image_hash, target_type, resize_param);
    memcached_return r;
    uint32_t flags;
    vlob = memcached_get(conf->memc, image_hash, strlen(image_hash), &vlob_length, &flags, &r);
    if(r==MEMCACHED_SUCCESS) {
      AP_LOG_DEBUG(rec, "Restored from memcached: %s, len=%d", image_hash, vlob_length);
      cache_hit = TRUE;
      goto WRITE_DATA;
    } else {
      AP_LOG_DEBUG(rec, "Can't restore from memcached: %s - %s(%d)", image_hash, memcached_strerror(conf->memc, r), r);
    }
  }

  // Reszize
  try {
    Magick::Image image;

    image.read(image_url);
    if(resize_param) image.zoom(resize_param);
    image.magick(target_type);
    image.quality(conf->jpeg_quality);
    image.write(&blob);
    vlob = (char*)blob.data();
    vlob_length = blob.length();
  }
  catch(Magick::Exception& err) {
    AP_LOG_ERR(rec, __FILE__ ": Magick failed: %s", err.what());
    goto PASS_THRU;
  }

  if(image_hash) {
    // Store to memcached...
    memcached_return r = memcached_set(conf->memc, image_hash, strlen(image_hash), vlob, vlob_length, conf->expire, 0);
    if(r==MEMCACHED_SUCCESS) {
      AP_LOG_DEBUG(rec, "Stored to memcached: %s(len=%d)", image_hash, vlob_length);
    } else {
      AP_LOG_DEBUG(rec, "Can't store from memcached: %s(len=%d) - %s(%d)", image_hash, vlob_length,memcached_strerror(conf->memc, r), r);
    }
  }

WRITE_DATA:
  AP_LOG_VERBOSE(rec, "-- Creating resize buckets.");

  // Drop all content and headers related.
  while(!APR_BRIGADE_EMPTY(in_bb)) {
    apr_bucket* b = APR_BRIGADE_FIRST(in_bb);
    apr_bucket_delete(b);
  }
  rec->eos_sent = 0;
  rec->clength = 0;
  unset_header(rec, "Content-Length");
  unset_header(rec, "Content-Encoding");
  unset_header(rec, "Last-Modified");
  unset_header(rec, "ETag");

  // Start resize bucket.
  {
    apr_off_t remain = vlob_length, offset = 0;
    while(remain>0) {
      apr_off_t bs = (remain<AP_MAX_SENDFILE)? remain: AP_MAX_SENDFILE;
      char* heap = (char*)malloc(bs);
      memcpy(heap, vlob+offset, bs);
      apr_bucket* b = apr_bucket_heap_create(heap, bs, free, in_bb-> bucket_alloc);
      APR_BRIGADE_INSERT_TAIL(in_bb, b);
      remain -= bs;
      offset += bs;
    }
    APR_BRIGADE_INSERT_TAIL(in_bb, apr_bucket_eos_create(in_bb->bucket_alloc));
    ap_set_content_length(rec, vlob_length);
    if(cache_hit) free(vlob);
  }
  AP_LOG_VERBOSE(rec, "-- Create done.");
 
PASS_THRU:
  AP_LOG_VERBOSE(rec, "-- Filter done.");
  ap_remove_output_filter(f);
  return ap_pass_brigade(f->next, in_bb);
}


// Add output filter if it is enabled.
static void resize_insert_output_filter(request_rec* rec)
{
  AP_LOG_VERBOSE(rec, "Incoming %s.", __FUNCTION__);
  resize_conf* conf = (resize_conf*)ap_get_module_config(rec->per_dir_config, &resizeimage_module);
  if(conf->enabled) ap_add_output_filter(X_RESIZE, NULL, rec, rec->connection);
}


//
// Configurators, and Register.
// 
static void* config_create(apr_pool_t* p, char* path)
{
  resize_conf* conf = (resize_conf*)apr_palloc(p, sizeof(resize_conf));
  conf->enabled = FALSE;
  conf->expire = 600;
  conf->memc = memcached_create(NULL);

  return conf;
}

static const char* append_server(cmd_parms* parms, void* _conf, const char* w1, const char* w2)
{
  memcached_return r;
  resize_conf* conf = (resize_conf*)_conf;
  memcached_server_st* servers;
  int port = atoi(w2);
  if(port<=0 || port>65535) return "Bad port number.";

  servers = memcached_server_list_append(NULL, w1, port, &r);
  if(r!=MEMCACHED_SUCCESS) return "memcached_server_list_append() failed.";

  r = memcached_server_push(conf->memc, servers);
  if(r!=MEMCACHED_SUCCESS) {
    memcached_server_list_free(servers);
    return "memcached_server_push() failed.";
  }
  memcached_server_list_free(servers);

  return NULL;
}

static const command_rec config_cmds[] = {
  AP_INIT_FLAG(X_RESIZE, (cmd_func)ap_set_flag_slot, (void*)APR_OFFSETOF(resize_conf, enabled), OR_OPTIONS, "{On|Off}"),
  AP_INIT_TAKE2(RESIZE "-cache",  (cmd_func)append_server, NULL, OR_OPTIONS, "server, port"),
  AP_INIT_TAKE1(RESIZE "-expire", (cmd_func)ap_set_int_slot, (void*)APR_OFFSETOF(resize_conf, expire), OR_OPTIONS, "expire(sec)"),
  AP_INIT_TAKE1(RESIZE "-quality", (cmd_func)ap_set_int_slot, (void*)APR_OFFSETOF(resize_conf, jpeg_quality), OR_OPTIONS, "JPEG quality(~100)"),
  { NULL },
};

static void register_hooks(apr_pool_t *p)
{
  ap_register_output_filter(X_RESIZE, resize_output_filter, NULL, AP_FTYPE_CONTENT_SET);
  ap_hook_insert_filter(resize_insert_output_filter, NULL, NULL, APR_HOOK_FIRST);
}


// Dispatch list for API hooks.
module AP_MODULE_DECLARE_DATA resizeimage_module = {
  STANDARD20_MODULE_STUFF, 
  config_create,  // create per-dir    config structures.
  NULL,           // merge  per-dir    config structures.
  NULL,           // create per-server config structures.
  NULL,           // merge  per-server config structures.
  config_cmds,    // table of config file commands.
  register_hooks  // register hooks.
};
