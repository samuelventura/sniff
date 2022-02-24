#include "sniff.h"
#include "erl_nif.h"

#include <stdio.h>
#include <string.h>

ErlNifResourceType *RES_TYPE;
ERL_NIF_TERM atom_ok;
ERL_NIF_TERM atom_er;

const char* _serial_close(SNIFF_RESOURCE *res) {
  //enif_fprintf(stdout, "_serial_close\n");
  if (res->open > 0) {
    if (res->closed == 0) {
      const char* error = serial_close(res);
      res->closed = 1;
      if (res->listen > 0) {
        //enif_thread_join(res->thread, NULL);
      }
      return error;
    }
  }
  return NULL;
}

void release_resource(ErlNifEnv *env, void *obj) {
  UNUSED(env);
  SNIFF_RESOURCE *res = obj;
  _serial_close(res);
}

static void down(ErlNifEnv *env, void *obj, ErlNifPid *pid, 
  ErlNifMonitor* mon) {
  UNUSED(env);
  UNUSED(pid);
  UNUSED(mon);
  SNIFF_RESOURCE *res = obj;
  _serial_close(res);
}

static int open_resource(ErlNifEnv *env) {
  ErlNifResourceTypeInit callbacks;
  callbacks.down = down;
  callbacks.dtor = release_resource;
  callbacks.stop = NULL;
  RES_TYPE = enif_open_resource_type_x(
      env, "Elixir.Sniff", &callbacks,
      ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
  if (RES_TYPE == NULL) return -1;
  return 0;
}

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info) {
  UNUSED(priv);
  UNUSED(load_info);
  if (open_resource(env) == -1) return -1;
  atom_ok = enif_make_atom(env, "ok");
  atom_er = enif_make_atom(env, "er");
  return 0;
}

static int reload(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info) {
  UNUSED(priv);
  UNUSED(load_info);
  if (open_resource(env) == -1) return -1;
  return 0;
}

static int upgrade(ErlNifEnv *env, void **priv, void **old_priv,
                   ERL_NIF_TERM load_info) {
  UNUSED(priv);
  UNUSED(old_priv);
  UNUSED(load_info);
  if (open_resource(env) == -1) return -1;
  return 0;
}

static ERL_NIF_TERM nif_open(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[]) {
  if (argc != 3) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Invalid argument count", ERL_NIF_LATIN1));
  }
  ErlNifBinary device;
  if (!enif_inspect_binary(env, argv[0], &device)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 0 is not a binary", ERL_NIF_LATIN1));
  }
  if (device.size > MAXPATH - PADSIZE) {
    return enif_make_tuple2(
        env, atom_er, enif_make_string(env, "Invalid device", ERL_NIF_LATIN1));
  }
  int speed;
  if (!enif_get_int(env, argv[1], &speed)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 1 is not an integer", ERL_NIF_LATIN1));
  }
  if (speed <= 0 || speed >= 0x7FFFFFFF) {
    return enif_make_tuple2(
        env, atom_er, enif_make_string(env, "Invalid speed", ERL_NIF_LATIN1));
  }
  ErlNifBinary config;
  if (!enif_inspect_binary(env, argv[2], &config)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 2 is not a binary", ERL_NIF_LATIN1));
  }
  if (config.size != 3) {
    return enif_make_tuple2(
        env, atom_er, enif_make_string(env, "Invalid config", ERL_NIF_LATIN1));
  }
  ErlNifPid self;
  if (enif_self(env, &self) == NULL) {
    return enif_make_tuple2(
        env, atom_er, enif_make_string(env, "Invalid self", ERL_NIF_LATIN1));
  }
  SNIFF_RESOURCE *res =
      (SNIFF_RESOURCE *)enif_alloc_resource(RES_TYPE, sizeof(SNIFF_RESOURCE));
  if (res == NULL) {
    return enif_raise_exception(
        env,
        enif_make_string(env, "enif_alloc_resource failed", ERL_NIF_LATIN1));
  }
  ERL_NIF_TERM resterm = enif_make_resource(env, res);
  enif_release_resource(res);
  strncpy(res->device, (const char *)device.data, device.size);
  strncpy(res->config, (const char *)config.data, config.size);
  res->device[device.size] = 0;
  res->config[config.size] = 0;
  res->fd = OPEN_ERROR;
  res->open = 0;
  res->closed = 0;
  res->listen = 0;
  res->self = self;  
  res->open = 1;
  const char* error = serial_open(res, speed);
  //return enif_make_tuple2(env, atom_er, enif_make_string(env, "HERE!", ERL_NIF_LATIN1));
  if (error != NULL) {
    _serial_close(res);
    //report serial_open error
    return enif_make_tuple2(env, atom_er,
                            enif_make_string(env, error, ERL_NIF_LATIN1));
  }
  ErlNifMonitor monitor;
  int r = enif_monitor_process(env, res, &self, &monitor);
  if (r > 0) {
    _serial_close(res);
    return enif_raise_exception(env,
        enif_make_string(env, "owner process no longer alive", ERL_NIF_LATIN1));
  } else if (r < 0) {
    _serial_close(res);
    return enif_raise_exception(env,
        enif_make_string(env, "enif_monitor_process failed", ERL_NIF_LATIN1));
  }
  return enif_make_tuple2(env, atom_ok, resterm);
}

static ERL_NIF_TERM nif_read(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Invalid argument count", ERL_NIF_LATIN1));
  }
  SNIFF_RESOURCE *res = NULL;
  if (!enif_get_resource(env, argv[0], RES_TYPE, (void **)&res)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 0 is not a resource", ERL_NIF_LATIN1));
  }
  if (res->closed > 0) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Already closed", ERL_NIF_LATIN1));
  }
  if (res->listen > 0) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Already listening", ERL_NIF_LATIN1));
  }
  COUNT count = 0;
  const char* error = serial_available(res, &count);
  if (error != NULL) {
    return enif_make_tuple2(env, atom_er,
                            enif_make_string(env, error, ERL_NIF_LATIN1));
  }
  if (count < 0) {
    return enif_make_tuple2(env, atom_er, enif_make_int(env, count));
  }
  ErlNifBinary bin;
  if (!enif_alloc_binary(count, &bin)) {
    return enif_raise_exception(
        env, enif_make_string(env, "enif_alloc_binary failed", ERL_NIF_LATIN1));
  }
  COUNT pcount = 0;
  error = serial_read(res, bin.data, (COUNT)bin.size, &pcount);
  if (error != NULL) {
    enif_release_binary(&bin);
    return enif_make_tuple2(env, atom_er,
                            enif_make_string(env, error, ERL_NIF_LATIN1));
  }
  return enif_make_tuple2(env, atom_ok, enif_make_binary(env, &bin));
}

static ERL_NIF_TERM nif_write(ErlNifEnv *env, int argc,
                              const ERL_NIF_TERM argv[]) {
  if (argc != 2) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Invalid argument count", ERL_NIF_LATIN1));
  }
  SNIFF_RESOURCE *res = NULL;
  if (!enif_get_resource(env, argv[0], RES_TYPE, (void **)&res)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 0 is not a resource", ERL_NIF_LATIN1));
  }
  if (res->closed > 0) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Already closed", ERL_NIF_LATIN1));
  }
  ErlNifBinary bin;
  if (!enif_inspect_binary(env, argv[1], &bin)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 1 is not a binary", ERL_NIF_LATIN1));
  }
  const char* error = serial_write(res, bin.data, (COUNT)bin.size);
  if (error != NULL) {
    return enif_make_tuple2(env, atom_er,
                            enif_make_string(env, error, ERL_NIF_LATIN1));
  }
  return atom_ok;
}

static void* nif_thread(void *ptr) {
  SNIFF_RESOURCE *res;
  res = (SNIFF_RESOURCE *)ptr;
  ErlNifEnv *env;
  if ((env = enif_alloc_env()) == NULL) {
    enif_raise_exception(
        env, enif_make_string(env, "enif_alloc_env failed", ERL_NIF_LATIN1));
  }
  ERL_NIF_TERM atom_sniff;
  ERL_NIF_TERM term_self;
  atom_sniff = enif_make_atom(env, "sniff");
  term_self = enif_make_pid(env, &res->self);
  int r = enif_send(NULL, &(res->self), NULL, term_self);
  enif_fprintf(stdout, "enif_send %d\n", r);

  const char* error = serial_block(res);
  if (error == NULL) {
    while (1) {
      ErlNifBinary bin;
      if (!enif_alloc_binary(256, &bin)) { break; }
      COUNT count = 0;
      enif_fprintf(stdout, "serial_read...\n");
      error = serial_read(res, bin.data, (COUNT)bin.size, &count);
      enif_fprintf(stdout, "serial_read %d %s\n", count, error);
      if (error != NULL && count <=0) { enif_release_binary(&bin); break; }
      if(!enif_realloc_binary(&bin, count)) { enif_release_binary(&bin); break; }
      ERL_NIF_TERM msg = enif_make_tuple3(env, atom_sniff, term_self, enif_make_binary(env, &bin));
      enif_send(NULL, &res->self, NULL, msg);
    }
  }

  enif_clear_env(env);
  
  enif_fprintf(stdout, "nif_thread exit\n");
  return NULL;
}

static ERL_NIF_TERM nif_listen(ErlNifEnv *env, int argc,
                              const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Invalid argument count", ERL_NIF_LATIN1));
  }
  SNIFF_RESOURCE *res = NULL;
  if (!enif_get_resource(env, argv[0], RES_TYPE, (void **)&res)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 0 is not a resource", ERL_NIF_LATIN1));
  }
  if (res->closed > 0) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Already closed", ERL_NIF_LATIN1));
  }
  if (res->listen > 0) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Already listening", ERL_NIF_LATIN1));
  }
  if (enif_thread_create("SNIFF_THREAD", &res->thread, nif_thread, (void*)res, NULL)!=0) {
    return enif_raise_exception(
        env, enif_make_string(env, "enif_thread_create failed", ERL_NIF_LATIN1));
  }
  res->listen = 1;
  return atom_ok;
}

static ERL_NIF_TERM nif_close(ErlNifEnv *env, int argc,
                              const ERL_NIF_TERM argv[]) {
  enif_fprintf(stdout, "nif_close\n");
  if (argc != 1) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Invalid argument count", ERL_NIF_LATIN1));
  }
  SNIFF_RESOURCE *res = NULL;
  if (!enif_get_resource(env, argv[0], RES_TYPE, (void **)&res)) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Argument 0 is not a resource", ERL_NIF_LATIN1));
  }
  if (res->closed > 0) {
    return enif_make_tuple2(
        env, atom_er,
        enif_make_string(env, "Already closed", ERL_NIF_LATIN1));
  }
  const char* error = _serial_close(res);
  if (error != NULL) {
    return enif_make_tuple2(env, atom_er,
                            enif_make_string(env, error, ERL_NIF_LATIN1));
  }
  return atom_ok;
}

static ErlNifFunc nif_funcs[] = {{"open", 3, nif_open, 0},
                                 {"read", 1, nif_read, 0},
                                 {"write", 2, nif_write, 0},
                                 {"listen", 1, nif_listen, 0},
                                 {"close", 1, nif_close, 0}};

ERL_NIF_INIT(Elixir.Sniff, nif_funcs, &load, &reload, &upgrade, NULL)
