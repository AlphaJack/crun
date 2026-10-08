/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020, 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include <config.h>
#include "../custom-handler.h"
#include "../container.h"
#include "../utils.h"
#include "../linux.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <ocispec/runtime_spec_schema_config_schema.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_LIBKRUN
#  include <libkrun.h>
#  include <libkrun_init.h>
#  include <libkrun_display.h>
#endif

/* libkrun has a hard-limit of 16 vCPUs per microVM. */
#define LIBKRUN_MAX_VCPUS 16

/* If the user doesn't configure the RAM amount, fallback to this value. */
#define LIBKRUN_DEFAULT_RAM_MIB 1024

/* The minimum amount of RAM for a viable microVM is 128 MB. */
#define LIBKRUN_MINIMUM_RAM_MIB 128

/* Default to a conservative DAX size of 512MB, just like libkrun 1.x krun_set_root() did. */
#define LIBKRUN_DEFAULT_VIRTIOFS_SHM_SIZE (512 * 1024 * 1024ULL)

/* virtio-net feature bits negotiated with the guest (same set as libkrun's examples). */
#define LIBKRUN_COMPAT_NET_FEATURES ((1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14))

#define LIBKRUN_GUEST_CID 3

/* The presence of this file indicates this is a container intended to be run
 * as a confidential workload inside a SEV-powered TEE.
 */
#define KRUN_SEV_FILE "/krun-sev.json"

#define KRUN_SEV_ROOT_DISK "/disk.img"

/* This file contains configuration parameters for the microVM. crun needs to
 * read and parse it, using the information obtained from it to configure
 * libkrun as required.
 */
#define KRUN_VM_FILE "/.krun_vm.json"

#define KRUN_FLAVOR_AWS_NITRO "aws-nitro"
#define KRUN_FLAVOR_SEV "sev"

#define FD_PAIR_PARENT 0
#define FD_PAIR_CHILD 1

/* The guest init control server (libkrun_init "control socket").  The VMM exposes
 * it as a Unix socket in the container's /dev tmpfs, which exists for read-only
 * containers too and goes away with the container.  `krun exec` reaches it from
 * inside the container, `krun kill` through /proc/<vmm pid>/root.
 */
#define KRUN_CONTROL_SOCKET "/dev/krun-init.sock"
#define KRUN_CONTROL_EXEC_TIMEOUT_MS 10000
#define KRUN_CONTROL_KILL_TIMEOUT_MS 2000

struct krun_config
{
  void *handle;
  void *handle_sev;
  void *handle_awsnitro;
  void *handle_init;
  bool sev;
  bool awsnitro;
  bool has_kvm;
  bool has_awsnitro;
  int passt_fds[2];
  json_object *config_doc;
  json_object *config_tree;
  bool use_passt;
  const char *tap_name;
  int gpu_flags;
  char *oci_config_json;
  size_t oci_config_json_size;
  KrunPayload payload;
  bool exec_enabled;
  KrunInitController controller;
};

/* libkrun handler.  */
#if HAVE_DLOPEN && HAVE_LIBKRUN

static void *
libkrun_dlsym (void *handle, const char *name, libcrun_error_t *err)
{
  void *sym = dlsym (handle, name);
  if (sym == NULL)
    {
      crun_make_error (err, 0, "could not find symbol `%s` in the krun library", name);
      return NULL;
    }
  return sym;
}

/* For the container process, where there is nobody left to report errors to.  */
static void *
libkrun_dlsym_or_die (void *handle, const char *name)
{
  void *sym = dlsym (handle, name);
  if (sym == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol `%s` in the krun library", name);
  return sym;
}

#  define KRUN_SYM(handle, name) ((name##_fn) libkrun_dlsym_or_die (handle, #name))

static bool
libkrun_errmsg_push (void *userdata, KrunStr s)
{
  char **buf = userdata;
  size_t cur = *buf ? strlen (*buf) : 0;
  char *tmp;

  tmp = realloc (*buf, cur + s.len + 1);
  if (tmp == NULL)
    return false;
  memcpy (tmp + cur, s.data, s.len);
  tmp[cur + s.len] = '\0';
  *buf = tmp;
  return true;
}

/* Return a malloc'ed description of KRUN_ERR and destroy it.  */
static char *
libkrun_error_string (void *handle, KrunError krun_err)
{
  krun_error_message_fn message = dlsym (handle, "krun_error_message");
  krun_error_destroy_fn destroy = dlsym (handle, "krun_error_destroy");
  KrunPushStrVtable vtable = { .drop = NULL, .push = libkrun_errmsg_push };
  char *msg = NULL;
  KrunVtableHandle writer = KRUN_VTABLE_HANDLE (KRUN_PUSH_STR_TYPE_TAG, vtable, &msg);

  if (krun_err == NULL)
    return xstrdup ("unknown error");
  if (message)
    message (krun_err, &writer);
  if (destroy)
    destroy (krun_err);
  return msg ? msg : xstrdup ("unknown error");
}

static char *
libkrun_init_error_string (void *handle_init, KrunInitError init_err)
{
  krun_init_error_message_fn message = dlsym (handle_init, "krun_init_error_message");
  krun_init_error_destroy_fn destroy = dlsym (handle_init, "krun_init_error_destroy");
  KrunInitPushStrVtable vtable = { .drop = NULL, .push = libkrun_errmsg_push };
  char *msg = NULL;
  KrunVtableHandle writer = KRUN_VTABLE_HANDLE (KRUN_INIT_PUSH_STR_TYPE_TAG, vtable, &msg);

  if (init_err == NULL)
    return xstrdup ("unknown error");
  if (message)
    message (init_err, &writer);
  if (destroy)
    destroy (init_err);
  return msg ? msg : xstrdup ("unknown error");
}

static void
libkrun_die_on_error (void *handle, KrunError krun_err, const char *what)
{
  if (krun_err == NULL)
    return;
  error (EXIT_FAILURE, 0, "%s: %s", what, libkrun_error_string (handle, krun_err));
}

static int
libkrun_read_vm_config (struct krun_config *kconf, int rootfsfd, const char *rootfs, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *config = NULL;
  cleanup_close int fd = -1;

  fd = safe_openat (rootfsfd, rootfs, KRUN_VM_FILE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0, err);
  if (fd < 0)
    {
      // The configuration file is optional, don't generate an error if it's missing.
      if (crun_error_get_errno (err) == ENOENT)
        {
          crun_error_release (err);
          return 0;
        }
      return fd;
    }

  ret = read_all_fd (fd, "krun configuration file", &config, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = parse_json_file (&kconf->config_doc, config, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  kconf->config_tree = kconf->config_doc;
  return 0;
}

/*
 * Default to parsing the OCI annotations to find the specified microVM
 * attribute. If the desired attribute is not found within the OCI annotations
 * or the krun_vm.json file, then return a negative integer.
 *
 * The configuration precedence is as follows:
 * OCI annotations -> krun_vm.json.
 * The config file is only used if "use_config_file" is "true".
 */
static int
libkrun_parse_resource_configuration (json_object *config_tree, libcrun_container_t *container, const char *annotation, const char *key, bool use_config_file)
{
  char *val_str, *endptr;
  int val = -1;
  json_object *val_json = NULL;

  val_str = (char *) find_annotation (container, annotation);
  if (val_str != NULL)
    {
      errno = 0;
      val = (int) strtol (val_str, &endptr, 10);
      if (errno != 0 || endptr == val_str || *endptr != '\0')
        /* Annotations value is not a valid integer. */
        error (EXIT_FAILURE, 0, "krun annotation %s value cannot be converted to an integer", annotation);

      if (val < 0)
        error (EXIT_FAILURE, 0, "krun annotation %s value must be a positive integer", annotation);

      return val;
    }
  else if (use_config_file && config_tree != NULL)
    {
      val_json = json_object_object_get (config_tree, key);
      if (val_json == NULL)
        return val;
      if (! json_object_is_type (val_json, json_type_int))
        error (EXIT_FAILURE, 0, "krun krun_vm.json %s value is not an integer", key);

      val = (int) json_object_get_int64 (val_json);
    }

  return val;
}

static int
libkrun_parse_string_configuration (json_object *config_tree, libcrun_container_t *container,
                                    const char *annotation, const char *key,
                                    const char **value, libcrun_error_t *err, bool use_config_file)
{
  const char *val;
  json_object *val_json = NULL;

  *value = NULL;

  val = find_annotation (container, annotation);
  if (val != NULL)
    {
      *value = val;
      return 0;
    }

  if (! use_config_file || config_tree == NULL)
    return 0;

  val_json = json_object_object_get (config_tree, key);
  if (val_json == NULL)
    return 0;

  if (! json_object_is_type (val_json, json_type_string))
    return crun_make_error (err, 0, ".krun_vm.json %s value is not a string", key);

  *value = json_object_get_string (val_json);
  return 0;
}

static bool
libkrun_exec_enabled (libcrun_container_t *container)
{
  return libkrun_parse_resource_configuration (NULL, container, "krun.exec", "exec", false) > 0;
}

static const char *
libkrun_config_string (json_object *config_tree, const char *key)
{
  json_object *val;

  if (config_tree == NULL)
    return NULL;

  val = json_object_object_get (config_tree, key);
  if (val == NULL || ! json_object_is_type (val, json_type_string))
    return NULL;

  return json_object_get_string (val);
}

static bool
libkrun_uses_external_kernel (struct krun_config *kconf, libcrun_container_t *container)
{
  json_object *kernel_format;

  if (kconf->config_tree == NULL)
    return false;

  if (libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.custom_kernel", "custom_kernel", false) <= 0)
    return false;

  /* kernel_path and kernel_format must be present, otherwise fall back to libkrunfw.  */
  if (libkrun_config_string (kconf->config_tree, "kernel_path") == NULL)
    return false;

  kernel_format = json_object_object_get (kconf->config_tree, "kernel_format");
  return kernel_format != NULL && json_object_is_type (kernel_format, json_type_int);
}

static void
libkrun_make_tap_mac (const char *id, uint8_t mac[6])
{
  uint64_t hash = 14695981039346656037ULL;
  size_t i;

  for (; *id != '\0'; id++)
    {
      hash ^= (uint8_t) *id;
      hash *= 1099511628211ULL;
    }

  for (i = 0; i < 6; i++)
    mac[i] = (uint8_t) (hash >> (i * 8));

  mac[0] = (mac[0] & 0xfe) | 0x02;
}

static int
libkrun_configure_flavor (struct krun_config *kconf, libcrun_container_t *container, libcrun_error_t *err)
{
  const char *flavor = find_annotation (container, "krun.variant");
  bool sev_indicated = flavor != NULL && strcmp (flavor, KRUN_FLAVOR_SEV) == 0;
  bool awsnitro_indicated = flavor != NULL && strcmp (flavor, KRUN_FLAVOR_AWS_NITRO) == 0;
  void *close_handles[2] = { NULL, NULL };
  int i, ret;

  if (sev_indicated)
    {
      if (kconf->handle_sev == NULL)
        return crun_make_error (err, 0, "the container requires libkrun-sev but it's not available");

      close_handles[0] = kconf->handle;
      close_handles[1] = kconf->handle_awsnitro;
      kconf->handle = kconf->handle_sev;
      kconf->sev = true;
    }
  else if (awsnitro_indicated)
    {
      if (kconf->handle_awsnitro == NULL)
        return crun_make_error (err, 0, "the container requires libkrun-awsnitro but it's not available");

      close_handles[0] = kconf->handle;
      close_handles[1] = kconf->handle_sev;
      kconf->handle = kconf->handle_awsnitro;
      kconf->awsnitro = true;
    }
  else
    {
      if (kconf->handle == NULL)
        return crun_make_error (err, 0, "the container requires libkrun but it's not available");

      close_handles[0] = kconf->handle_sev;
      close_handles[1] = kconf->handle_awsnitro;
    }

  /* The selected flavor now lives in kconf->handle; the other handles are no longer needed.  */
  kconf->handle_sev = NULL;
  kconf->handle_awsnitro = NULL;

  for (i = 0; i < 2; i++)
    {
      if (close_handles[i] == NULL)
        continue;

      ret = dlclose (close_handles[i]);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
    }

  return 0;
}

/* Load the kernel payload while the host file system is still visible.  libkrunfw is
   a shared library that is dlopen'ed by libkrun, so it must be loaded before the
   container enters its mount namespace.  External kernels live in the rootfs and are
   loaded from inside the container instead, so that symlinks cannot escape it.  */
static int
libkrun_load_payload (struct krun_config *kconf, int rootfsfd, const char *rootfs, libcrun_container_t *container, libcrun_error_t *err)
{
  KrunError krun_err = NULL;

  if (kconf->awsnitro || libkrun_uses_external_kernel (kconf, container))
    return 0;

  if (kconf->sev)
    {
      krun_payload_load_krunfw_tee_fn load_krunfw_tee;
      cleanup_free char *fd_path = NULL;
      cleanup_close int fd = -1;

      load_krunfw_tee = libkrun_dlsym (kconf->handle, "krun_payload_load_krunfw_tee", err);
      if (load_krunfw_tee == NULL)
        return -1;

      /* CVE-2025-24965: the content below rootfs cannot be trusted because it is controlled by the user.  We
         must ensure the file is opened below the rootfs directory.  */
      fd = safe_openat (rootfsfd, rootfs, KRUN_SEV_FILE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0, err);
      if (UNLIKELY (fd < 0))
        return fd;

      xasprintf (&fd_path, "/proc/self/fd/%d", fd);
      kconf->payload = load_krunfw_tee (KRUN_STR (fd_path), KRUN_STR (NULL), &krun_err);
    }
  else
    {
      krun_payload_load_krunfw_fn load_krunfw;

      load_krunfw = libkrun_dlsym (kconf->handle, "krun_payload_load_krunfw", err);
      if (load_krunfw == NULL)
        return -1;

      kconf->payload = load_krunfw (&krun_err);
    }

  if (krun_err != NULL || kconf->payload == NULL)
    {
      cleanup_free char *msg = libkrun_error_string (kconf->handle, krun_err);
      kconf->payload = NULL;
      return crun_make_error (err, 0, "could not load the krun kernel payload: %s", msg);
    }

  return 0;
}

static void
libkrun_setup_logging (void *handle)
{
  krun_init_log_fn init_log = KRUN_SYM (handle, krun_init_log);
  KrunError krun_err = NULL;
  uint32_t level;

  /* Set log level according to crun's verbosity. */
  switch (libcrun_get_verbosity ())
    {
    case LIBCRUN_VERBOSITY_DEBUG:
      level = KRUN_LOG_LEVEL_DEBUG;
      break;
    case LIBCRUN_VERBOSITY_WARNING:
      level = KRUN_LOG_LEVEL_WARN;
      break;
    default:
      level = KRUN_LOG_LEVEL_ERROR;
      break;
    }

  init_log (-1, level, KRUN_LOG_STYLE_NEVER, 0, &krun_err);
  if (krun_err != NULL)
    {
      cleanup_free char *msg = libkrun_error_string (handle, krun_err);
      libcrun_warning ("could not initialize krun logging: %s", msg);
    }
}

static KrunPayload
libkrun_external_kernel_payload (struct krun_config *kconf)
{
  krun_payload_load_external_fn load_external = KRUN_SYM (kconf->handle, krun_payload_load_external);
  const char *kernel_path = libkrun_config_string (kconf->config_tree, "kernel_path");
  const char *initrd_path = libkrun_config_string (kconf->config_tree, "initrd_path");
  const char *kernel_cmdline = libkrun_config_string (kconf->config_tree, "kernel_cmdline");
  uint32_t kernel_format = (uint32_t) json_object_get_int64 (json_object_object_get (kconf->config_tree, "kernel_format"));
  KrunError krun_err = NULL;
  KrunPayload payload;

  payload = load_external (KRUN_STR (kernel_path), kernel_format, KRUN_STR (initrd_path), KRUN_STR (kernel_cmdline), &krun_err);
  libkrun_die_on_error (kconf->handle, krun_err, "could not configure a krun external kernel");
  if (payload == NULL)
    error (EXIT_FAILURE, 0, "could not configure a krun external kernel");
  return payload;
}

static char *
libkrun_join_strings (char *const strings[], size_t count, char sep)
{
  size_t len = 1, i;
  char *out, *p;

  for (i = 0; i < count; i++)
    len += strlen (strings[i]) + 1;

  out = p = xmalloc (len);
  for (i = 0; i < count; i++)
    {
      size_t n = strlen (strings[i]);

      if (i > 0)
        *p++ = sep;
      memcpy (p, strings[i], n);
      p += n;
    }
  *p = '\0';
  return out;
}

static KrunPayload
libkrun_nitro_payload (struct krun_config *kconf, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = container->container_def;
  void *handle = kconf->handle;
  KrunNitroConfig nitro = KRUN_SYM (handle, krun_nitro_config_new) ();
  size_t argc = 0, env_len = def->process ? def->process->env_len : 0;
  cleanup_free char *args = NULL;
  cleanup_free char *env = NULL;
  KrunError krun_err = NULL;
  KrunPayload payload;

  while (argv[argc])
    argc++;
  args = libkrun_join_strings (&argv[1], argc > 0 ? argc - 1 : 0, ' ');
  env = libkrun_join_strings (def->process ? def->process->env : NULL, env_len, ' ');

  KRUN_SYM (handle, krun_nitro_config_rootfs) (&nitro, KRUN_STR ("/"));
  KRUN_SYM (handle, krun_nitro_config_exec_path) (&nitro, KRUN_STR (pathname));
  KRUN_SYM (handle, krun_nitro_config_args) (&nitro, KRUN_STR (args));
  KRUN_SYM (handle, krun_nitro_config_env) (&nitro, KRUN_STR (env));
  if (def->process && def->process->cwd)
    KRUN_SYM (handle, krun_nitro_config_workdir) (&nitro, KRUN_STR (def->process->cwd));
  // Redirect all enclave output (read from vsock) to stdout.
  KRUN_SYM (handle, krun_nitro_config_console_output) (&nitro, KRUN_STR ("/dev/stdout"));
  if (kconf->use_passt)
    KRUN_SYM (handle, krun_nitro_config_net_fd) (&nitro, kconf->passt_fds[FD_PAIR_PARENT]);

  payload = KRUN_SYM (handle, krun_payload_nitro_enclave) (nitro, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not configure the enclave");
  if (payload == NULL)
    error (EXIT_FAILURE, 0, "could not configure the enclave");
  return payload;
}

/* Inject the init binary and its configuration into the guest root.  Returns the
   overlay that must be attached to the root virtiofs device.  */
static KrunFsOverlay
libkrun_apply_init_config (struct krun_config *kconf, KrunPayload payload, KrunInitBuilder *builder, KrunVsockDevice vsock)
{
  void *handle_init = kconf->handle_init;
  krun_init_builder_build_fn build = KRUN_SYM (handle_init, krun_init_builder_build);
  KrunFsOverlay overlay = KRUN_SYM (kconf->handle, krun_fs_overlay_new) ();
  KrunInitError init_err = NULL;
  KrunInitConfig config;

  config = build (builder);
  if (kconf->exec_enabled)
    KRUN_SYM (handle_init, krun_init_config_apply_with_vsock_in) (config, kconf->handle, overlay, payload, vsock, &init_err);
  else
    KRUN_SYM (handle_init, krun_init_config_apply_in) (config, kconf->handle, overlay, payload, &init_err);
  if (init_err != NULL)
    error (EXIT_FAILURE, 0, "could not apply the krun init configuration: %s", libkrun_init_error_string (handle_init, init_err));

  return overlay;
}

static KrunInitBuilder
libkrun_init_builder (struct krun_config *kconf)
{
  void *handle_init = kconf->handle_init;
  krun_init_builder_from_oci_json_fn from_oci_json = KRUN_SYM (handle_init, krun_init_builder_from_oci_json);
  KrunStr oci_json = { kconf->oci_config_json, kconf->oci_config_json_size };
  KrunInitError init_err = NULL;
  KrunInitBuilder builder;

  builder = from_oci_json (oci_json, &init_err);
  if (init_err != NULL)
    error (EXIT_FAILURE, 0, "could not parse the OCI configuration for the krun init: %s", libkrun_init_error_string (handle_init, init_err));

  if (kconf->use_passt)
    KRUN_SYM (handle_init, krun_init_builder_dhcp) (&builder, true);

  if (kconf->exec_enabled)
    KRUN_SYM (handle_init, krun_init_builder_control_socket) (&builder, KRUN_STR (KRUN_CONTROL_SOCKET));

  return builder;
}

static void
libkrun_add_console (void *handle, KrunMmioDeviceManager devices)
{
  KrunConsoleBuilder console_builder = KRUN_SYM (handle, krun_console_device_builder) ();
  KrunError krun_err = NULL;
  KrunConsoleDevice console;

  KRUN_SYM (handle, krun_console_builder_add_default_console) (console_builder, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not configure the virtio console");

  console = KRUN_SYM (handle, krun_console_builder_build) (console_builder, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not create the virtio console");

  KRUN_SYM (handle, krun_mmio_device_manager_add) (devices, console);
}

static void
libkrun_add_root_fs (struct krun_config *kconf, KrunMmioDeviceManager devices, KrunFsOverlay overlay)
{
  void *handle = kconf->handle;
  const char *virtiofs_tag = libkrun_config_string (kconf->config_tree, "virtiofs_tag");
  uint64_t virtiofs_shm_size = LIBKRUN_DEFAULT_VIRTIOFS_SHM_SIZE;
  json_object *val_virtiofs_shm_size = NULL;
  KrunError krun_err = NULL;
  KrunFsDevice rootfs;

  if (virtiofs_tag == NULL)
    virtiofs_tag = "/dev/root";

  if (kconf->config_tree != NULL)
    {
      val_virtiofs_shm_size = json_object_object_get (kconf->config_tree, "virtiofs_shm_size");
      if (val_virtiofs_shm_size != NULL && json_object_is_type (val_virtiofs_shm_size, json_type_int))
        virtiofs_shm_size = json_object_get_uint64 (val_virtiofs_shm_size);
    }

  rootfs = KRUN_SYM (handle, krun_fs_device_new) (KRUN_STR (virtiofs_tag), KRUN_STR ("/"), &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not add virtiofs root");

  KRUN_SYM (handle, krun_fs_device_set_overlay) (rootfs, overlay);
  if (virtiofs_shm_size > 0)
    KRUN_SYM (handle, krun_fs_device_set_dax_window_size) (rootfs, virtiofs_shm_size);

  KRUN_SYM (handle, krun_mmio_device_manager_add) (devices, rootfs);
}

static void
libkrun_add_root_disk (void *handle, KrunMmioDeviceManager devices)
{
  KrunError krun_err = NULL;
  KrunBlockDevice disk;

  disk = KRUN_SYM (handle, krun_block_device_new) (KRUN_STR ("root"), KRUN_STR (KRUN_SEV_ROOT_DISK), KRUN_DISK_FORMAT_RAW, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not set root disk");

  KRUN_SYM (handle, krun_mmio_device_manager_add) (devices, disk);
}

static KrunVsockDevice
libkrun_new_vsock (struct krun_config *kconf)
{
  void *handle = kconf->handle;
  uint32_t tsi_flags = (kconf->tap_name != NULL || kconf->use_passt) ? 0 : KRUN_TSI_FLAGS_HIJACK_INET;
  KrunError krun_err = NULL;
  KrunVsockDevice vsock;

  vsock = KRUN_SYM (handle, krun_vsock_device_new) (LIBKRUN_GUEST_CID, tsi_flags, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not create the vsock device");

  /* /dev is normally a fresh tmpfs, but with a bundle that lacks one a socket left
     behind by a previous run would make bind() fail.  */
  if (kconf->exec_enabled)
    unlink (KRUN_CONTROL_SOCKET);

  return vsock;
}

static void
libkrun_add_net (struct krun_config *kconf, libcrun_container_t *container, KrunMmioDeviceManager devices)
{
  void *handle = kconf->handle;
  KrunError krun_err = NULL;
  KrunNetDevice net;
  uint8_t mac[6];
  KrunBytes mac_bytes = { mac, sizeof (mac) };

  if (kconf->tap_name != NULL)
    {
      krun_net_device_new_tap_fn new_tap = dlsym (handle, "krun_net_device_new_tap");
      if (new_tap == NULL)
        error (EXIT_FAILURE, 0, "krun.tap_name requested but the version of libkrun in this system does not support virtio-net");

      libkrun_make_tap_mac (container->context->id, mac);
      net = new_tap (KRUN_STR ("net0"), KRUN_STR (kconf->tap_name), mac_bytes, LIBKRUN_COMPAT_NET_FEATURES, &krun_err);
      libkrun_die_on_error (handle, krun_err, "could not add krun TAP interface");
    }
  else if (kconf->use_passt)
    {
      static const uint8_t passt_mac[] = { 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee };
      krun_net_device_new_unixstream_fd_fn new_unixstream_fd = dlsym (handle, "krun_net_device_new_unixstream_fd");
      if (new_unixstream_fd == NULL)
        error (EXIT_FAILURE, 0, "krun.use_passt requested but the version of libkrun in this system does not support virtio-net");

      memcpy (mac, passt_mac, sizeof (mac));
      net = new_unixstream_fd (KRUN_STR ("net0"), kconf->passt_fds[FD_PAIR_PARENT], mac_bytes, LIBKRUN_COMPAT_NET_FEATURES, 0, &krun_err);
      libkrun_die_on_error (handle, krun_err, "could not set krun net configuration");
    }
  else
    return;

  KRUN_SYM (handle, krun_mmio_device_manager_add) (devices, net);
}

static void
libkrun_add_gpu (struct krun_config *kconf, KrunMmioDeviceManager devices)
{
  void *handle = kconf->handle;
  krun_display_backend_new_fn display_backend_new = dlsym (handle, "krun_display_backend_new");
  krun_gpu_device_new_fn gpu_device_new = dlsym (handle, "krun_gpu_device_new");
  /* Headless: the GPU is used for compute (e.g. Venus) and has no scanouts.  */
  struct krun_display_backend headless = { 0 };
  KrunError krun_err = NULL;
  KrunDisplayBackend backend;
  KrunGpuDevice gpu;

  if (display_backend_new == NULL || gpu_device_new == NULL)
    error (EXIT_FAILURE, 0, "gpu requested but the version of libkrun in this system does not support it");

  if (kconf->gpu_flags & KRUN_VIRGL_RENDERER_FLAGS_RENDER_SERVER)
    libcrun_warning ("krun.gpu_flags requests the virgl render server: libkrun 2.0 spawns it itself, the sandboxed launcher used with libkrun 1.x is not available");

  backend = display_backend_new (&headless, sizeof (headless), &krun_err);
  libkrun_die_on_error (handle, krun_err, "gpu requested but could not create the display backend");

  gpu = gpu_device_new (kconf->gpu_flags, backend);
  KRUN_SYM (handle, krun_mmio_device_manager_add) (devices, gpu);
}

static void
libkrun_add_misc_devices (void *handle, KrunMmioDeviceManager devices)
{
  krun_rng_device_new_fn rng_new = dlsym (handle, "krun_rng_device_new");
  krun_balloon_device_new_fn balloon_new = dlsym (handle, "krun_balloon_device_new");
  krun_mmio_device_manager_add_fn add = KRUN_SYM (handle, krun_mmio_device_manager_add);
  KrunError krun_err = NULL;

  if (rng_new != NULL)
    {
      KrunRngDevice rng = rng_new (&krun_err);
      libkrun_die_on_error (handle, krun_err, "could not create the virtio-rng device");
      add (devices, rng);
    }

  if (balloon_new != NULL)
    {
      KrunBalloonDevice balloon = balloon_new (&krun_err);
      libkrun_die_on_error (handle, krun_err, "could not create the virtio-balloon device");
      add (devices, balloon);
    }
}

static void
libkrun_configure_vm (struct krun_config *kconf, libcrun_container_t *container, KrunVmmBuilder *builder)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  void *handle = kconf->handle;
  KrunError krun_err = NULL;
  int cpus, ram_mib, nested_virt;
  cpu_set_t set;

  /* We let the OCI set the number of vCPUs for the VM, since cgroups CPU restrictions still apply. */
  cpus = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.cpus", "cpus", true);
  if (cpus <= 0)
    {
      CPU_ZERO (&set);
      if (sched_getaffinity (getpid (), sizeof (set), &set) == 0)
        cpus = MIN (CPU_COUNT (&set), LIBKRUN_MAX_VCPUS);
      else
        cpus = 1;
    }

  /* We let the OCI set the amount of RAM for the VM, since cgroups memory restrictions still apply. */
  ram_mib = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.ram_mib", "ram_mib", true);
  if (ram_mib <= LIBKRUN_MINIMUM_RAM_MIB)
    {
      if (def && def->linux && def->linux->resources && def->linux->resources->memory
          && def->linux->resources->memory->limit_present)
        ram_mib = def->linux->resources->memory->limit / (1024 * 1024);
      else
        ram_mib = LIBKRUN_DEFAULT_RAM_MIB;
    }

  KRUN_SYM (handle, krun_vmm_builder_vcpus) (builder, cpus, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not set the number of vCPUs");

  KRUN_SYM (handle, krun_vmm_builder_ram_mib) (builder, ram_mib, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not set the amount of RAM");

  nested_virt = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.nested_virt", "nested_virt", false);
  if (nested_virt > 0)
    {
      krun_check_nested_virt_fn check_nested_virt = dlsym (handle, "krun_check_nested_virt");

      if (check_nested_virt != NULL && ! check_nested_virt ())
        libcrun_warning ("nested virtualization requested but may not be supported on this host");

      KRUN_SYM (handle, krun_vmm_builder_nested_virt) (builder, true);
    }
}

static int
libkrun_exec (void *cookie, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  void *handle = kconf->handle;
  KrunError krun_err = NULL;
  KrunMmioDeviceManager devices = NULL;
  KrunPayload payload;
  KrunVmmBuilder builder;
  KrunVmm vmm;

  // /dev/kvm is required for all non AWS nitro workloads.
  if (! kconf->awsnitro && ! kconf->has_kvm)
    error (EXIT_FAILURE, 0, "`/dev/kvm` unavailable");

  libkrun_setup_logging (handle);

  if (kconf->awsnitro)
    payload = libkrun_nitro_payload (kconf, container, pathname, argv);
  else
    {
      KrunFsOverlay overlay = NULL;
      KrunVsockDevice vsock;

      payload = kconf->payload;
      if (payload == NULL)
        payload = libkrun_external_kernel_payload (kconf);

      vsock = libkrun_new_vsock (kconf);
      if (! kconf->sev)
        {
          KrunInitBuilder init_builder = libkrun_init_builder (kconf);
          overlay = libkrun_apply_init_config (kconf, payload, &init_builder, vsock);
        }

      devices = KRUN_SYM (handle, krun_mmio_device_manager_new) ();
      libkrun_add_console (handle, devices);
      if (kconf->sev)
        libkrun_add_root_disk (handle, devices);
      else
        libkrun_add_root_fs (kconf, devices, overlay);
      KRUN_SYM (handle, krun_mmio_device_manager_add) (devices, vsock);
      libkrun_add_net (kconf, container, devices);
      if (kconf->gpu_flags > 0)
        libkrun_add_gpu (kconf, devices);
      libkrun_add_misc_devices (handle, devices);
    }

  json_object_put (kconf->config_doc);
  kconf->config_doc = kconf->config_tree = NULL;

  builder = KRUN_SYM (handle, krun_vmm_builder_new) ();
  libkrun_configure_vm (kconf, container, &builder);
  KRUN_SYM (handle, krun_vmm_builder_payload) (&builder, payload);
  if (devices != NULL)
    KRUN_SYM (handle, krun_vmm_builder_devices) (&builder, devices);

  vmm = KRUN_SYM (handle, krun_vmm_builder_build) (&builder, &krun_err);
  libkrun_die_on_error (handle, krun_err, "could not start krun");

  /* Never returns: the process becomes the VMM and exits with the workload status.  */
  KRUN_SYM (handle, krun_vmm_run) (vmm);
  return 0;
}

static int
libkrun_configure_network (void *cookie, libcrun_container_t *container, libcrun_error_t *err)
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  pid_t pid;
  char *passt_argv[10];
  char fd_as_str[16];
  int use_passt;
  int argv_idx;
  int status;
  int null;
  int ret;

  ret = libkrun_parse_string_configuration (kconf->config_tree, container,
                                            "krun.tap_name", "tap_name",
                                            &kconf->tap_name, err, false);
  if (UNLIKELY (ret < 0))
    return ret;

  if (kconf->tap_name != NULL && is_empty_string (kconf->tap_name))
    return crun_make_error (err, 0, "krun.tap_name cannot be empty");

  use_passt = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.use_passt", "use_passt", false);

  if (use_passt > 0)
    {
      if (kconf->tap_name != NULL)
        return crun_make_error (err, 0, "krun.tap_name and krun.use_passt are mutually exclusive");

      kconf->use_passt = 1;
    }
  else
    return 0;

  ret = socketpair (AF_UNIX, SOCK_STREAM, 0, kconf->passt_fds);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "create passt socketpair");

  snprintf (fd_as_str, sizeof (fd_as_str), "%d", kconf->passt_fds[FD_PAIR_CHILD]);

  argv_idx = 0;
  passt_argv[argv_idx++] = (char *) "passt";
  passt_argv[argv_idx++] = (char *) "-t";
  passt_argv[argv_idx++] = (char *) "all";

  if (! kconf->has_awsnitro)
    {
      passt_argv[argv_idx++] = (char *) "-u";
      passt_argv[argv_idx++] = (char *) "all";
      passt_argv[argv_idx++] = (char *) "--no-dhcp-dns";
    }

  /* Set --no-map-gw. If the gateway for the network is also the DNS server
   * we won't be able to query the DNS server without --no-map-gw.
   * See discussion in https://github.com/containers/crun/pull/2099
   */
  passt_argv[argv_idx++] = (char *) "--no-map-gw";

  passt_argv[argv_idx++] = (char *) "--fd";
  passt_argv[argv_idx++] = fd_as_str;
  passt_argv[argv_idx] = NULL;

  pid = fork ();
  if (pid < 0)
    return crun_make_error (err, errno, "fork passt");
  else if (pid == 0)
    {
      close (kconf->passt_fds[FD_PAIR_PARENT]);

      null = open ("/dev/null", O_WRONLY);
      if (null == -1)
        _exit (EXIT_FAILURE);

      // Redirect passt's stdout and stderr to /dev/null, as closing them here
      // instead will cause passt to exit with an error.
      dup2 (null, STDOUT_FILENO);
      dup2 (null, STDERR_FILENO);
      close (null);

      execvp ("/usr/bin/passt", passt_argv);
      // Only reachable on error.
      _exit (EXIT_FAILURE);
    }

  close (kconf->passt_fds[FD_PAIR_CHILD]);

  // Wait for passt to daemonize itself.
  waitpid (pid, &status, 0);
  if (! (WIFEXITED (status)) || WEXITSTATUS (status) != 0)
    return crun_make_error (err, 0, "start passt");

  return 0;
}

/* Return true if the spec already declares a device with the given PATH.  */
static bool
spec_has_device (runtime_spec_schema_config_schema *def, const char *path)
{
  size_t i;

  for (i = 0; i < def->linux->devices_len; i++)
    if (strcmp (def->linux->devices[i]->path, path) == 0)
      return true;
  return false;
}

/* libkrun_create_kvm_device: explicitly adds kvm device.  */
static int
libkrun_configure_container (void *cookie, enum handler_configure_phase phase,
                             libcrun_context_t *context, libcrun_container_t *container,
                             const char *rootfs, libcrun_error_t *err)
{
  int ret, rootfsfd;
  struct krun_config *kconf = (struct krun_config *) cookie;
  struct device_s kvm_device = { "/dev/kvm", "c", 10, 232, 0666, 0, 0 };
  struct device_s sev_device = { "/dev/sev", "c", 10, 124, 0666, 0, 0 };
  struct device_s nitro_device = { "/dev/nitro_enclaves", "c", 10, 122, 0666, 0, 0 };
  cleanup_close int devfd = -1;
  cleanup_close int rootfsfd_cleanup = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  bool create_sev = false, create_awsnitro = false;
  bool is_user_ns;

  if (rootfs == NULL)
    rootfsfd = AT_FDCWD;
  else
    {
      rootfsfd = rootfsfd_cleanup = open (rootfs, O_PATH | O_CLOEXEC);
      if (UNLIKELY (rootfsfd < 0))
        return crun_make_error (err, errno, "open `%s`", rootfs);
    }

  if (phase == HANDLER_CONFIGURE_BEFORE_USERNS)
    {
      cleanup_free char *origin_config_path = NULL;
      cleanup_free char *state_dir = NULL;

      ret = libcrun_get_state_directory (&state_dir, context->state_root, context->id, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&origin_config_path, err, state_dir, "config.json", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      /* The OCI configuration is handed to libkrun_init, which injects the guest
         init and its configuration into the root file system.  */
      ret = read_all_file (origin_config_path, &kconf->oci_config_json, &kconf->oci_config_json_size, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libkrun_read_vm_config (kconf, rootfsfd, rootfs, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libkrun_configure_flavor (kconf, container, err);
      if (UNLIKELY (ret < 0))
        return ret;

      kconf->gpu_flags = libkrun_parse_resource_configuration (kconf->config_tree, container, "krun.gpu_flags", "gpu_flags", false);
      if (kconf->gpu_flags > 0 && access ("/dev/dri", F_OK) != 0)
        return crun_make_error (err, errno, "gpu requested but /dev/dri is not available");

      kconf->exec_enabled = libkrun_exec_enabled (container);
      if (kconf->exec_enabled && (kconf->sev || kconf->awsnitro))
        return crun_make_error (err, 0, "krun.exec is only supported with the default libkrun flavor");

      ret = libkrun_load_payload (kconf, rootfsfd, rootfs, container, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (phase != HANDLER_CONFIGURE_AFTER_MOUNTS)
    return 0;

  ret = libkrun_configure_network (cookie, container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Do nothing if /dev/kvm is already present in spec */
  if (spec_has_device (def, "/dev/kvm"))
    return 0;

  if (kconf->sev)
    create_sev = ! spec_has_device (def, "/dev/sev");

  if (kconf->awsnitro)
    create_awsnitro = ! spec_has_device (def, "/dev/nitro_enclaves");

  devfd = safe_openat (rootfsfd, rootfs, "dev", O_PATH | O_DIRECTORY | O_CLOEXEC, 0, err);
  if (UNLIKELY (devfd < 0))
    return devfd;

  ret = check_running_in_user_namespace (err);
  if (UNLIKELY (ret < 0))
    return ret;
  is_user_ns = ret;

  if (kconf->has_kvm)
    {
      ret = libcrun_create_dev (container, devfd, -1, &kvm_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (create_sev)
    {
      ret = libcrun_create_dev (container, devfd, -1, &sev_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (create_awsnitro)
    {
      ret = libcrun_create_dev (container, devfd, -1, &nitro_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
libkrun_load (void **cookie, libcrun_error_t *err)
{
  struct krun_config *kconf;
  const char *libkrun_so = "libkrun.so.2";
  const char *libkrun_sev_so = "libkrun-sev.so.2";
  const char *libkrun_awsnitro_so = "libkrun-awsnitro.so.2";
  const char *libkrun_init_so = "libkrun_init.so.0";

  kconf = xmalloc0 (sizeof (struct krun_config));

  kconf->handle = dlopen (libkrun_so, RTLD_NOW);
  kconf->handle_sev = dlopen (libkrun_sev_so, RTLD_NOW);
  kconf->handle_awsnitro = dlopen (libkrun_awsnitro_so, RTLD_NOW);

  if (kconf->handle == NULL && kconf->handle_sev == NULL && kconf->handle_awsnitro == NULL)
    {
      free (kconf);
      return crun_make_error (err, 0, "failed to open `%s`, `%s`, and `%s` for krun_config: %s", libkrun_so, libkrun_sev_so, libkrun_awsnitro_so, dlerror ());
    }

  /* libkrun_init provides the guest init binary and its configuration.  It is
     required for every flavor that boots from a shared root file system.  */
  kconf->handle_init = dlopen (libkrun_init_so, RTLD_NOW);
  if (kconf->handle_init == NULL)
    {
      int ret = crun_make_error (err, 0, "failed to open `%s`: %s", libkrun_init_so, dlerror ());

      if (kconf->handle)
        dlclose (kconf->handle);
      if (kconf->handle_sev)
        dlclose (kconf->handle_sev);
      if (kconf->handle_awsnitro)
        dlclose (kconf->handle_awsnitro);
      free (kconf);
      return ret;
    }

  *cookie = kconf;

  return 0;
}

static int
libkrun_unload (void *cookie, libcrun_error_t *err)
{
  int r;

  struct krun_config *kconf = (struct krun_config *) cookie;
  if (kconf != NULL)
    {
      if (kconf->payload != NULL)
        {
          krun_payload_destroy_fn payload_destroy = dlsym (kconf->handle, "krun_payload_destroy");
          if (payload_destroy != NULL)
            payload_destroy (kconf->payload);
        }
      if (kconf->handle != NULL)
        {
          r = dlclose (kconf->handle);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
        }
      if (kconf->handle_sev != NULL)
        {
          r = dlclose (kconf->handle_sev);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle_sev: `%s`", dlerror ());
        }
      if (kconf->handle_awsnitro != NULL)
        {
          r = dlclose (kconf->handle_awsnitro);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle_awsnitro: `%s`", dlerror ());
        }
      if (kconf->handle_init != NULL)
        {
          r = dlclose (kconf->handle_init);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle_init: `%s`", dlerror ());
        }
      if (kconf->config_doc != NULL)
        json_object_put (kconf->config_doc);
      if (kconf->controller != NULL)
        {
          krun_init_controller_destroy_fn controller_destroy = dlsym (kconf->handle_init, "krun_init_controller_destroy");
          if (controller_destroy != NULL)
            controller_destroy (kconf->controller);
        }
      free (kconf->oci_config_json);
      free (kconf);
    }
  return 0;
}

static runtime_spec_schema_defs_linux_device_cgroup *
make_oci_spec_dev (const char *type, dev_t device, bool allow, const char *access)
{
  runtime_spec_schema_defs_linux_device_cgroup *dev = xmalloc0 (sizeof (*dev));

  dev->allow = allow;
  dev->allow_present = 1;

  dev->type = xstrdup (type);

  dev->major = major (device);
  dev->major_present = 1;

  dev->minor = minor (device);
  dev->minor_present = 1;

  dev->access = xstrdup (access);

  return dev;
}

/* stat an optional device: on ENOENT clear *PRESENT, any other error fails.  */
static int
stat_optional_device (const char *path, struct stat *st, bool *present, libcrun_error_t *err)
{
  int ret = stat (path, st);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `%s`", path);
      *present = false;
    }
  return 0;
}

static int
libkrun_modify_oci_configuration (void *cookie arg_unused, libcrun_context_t *context arg_unused,
                                  runtime_spec_schema_config_schema *def,
                                  libcrun_error_t *err)
{
  const size_t device_size = sizeof (runtime_spec_schema_defs_linux_device_cgroup);
  struct krun_config *kconf = (struct krun_config *) cookie;
  struct stat st_kvm, st_sev, st_awsnitro;
  bool has_kvm = true, has_sev = true, has_awsnitro = true;
  size_t old_len, new_len;
  int ret;

  /* Always allow the /dev/kvm device.  */

  ret = stat_optional_device ("/dev/kvm", &st_kvm, &has_kvm, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = stat_optional_device ("/dev/sev", &st_sev, &has_sev, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = stat_optional_device ("/dev/nitro_enclaves", &st_awsnitro, &has_awsnitro, err);
  if (UNLIKELY (ret < 0))
    return ret;

  kconf->has_kvm = has_kvm;
  kconf->has_awsnitro = has_awsnitro;

  if (! has_kvm && ! has_awsnitro)
    return 0;

  /* spec says these are optional, ensure they exist so we can add our devices */
  if (def->linux == NULL)
    def->linux = xmalloc0 (sizeof (runtime_spec_schema_config_linux));

  if (def->linux->resources == NULL)
    def->linux->resources = xmalloc0 (sizeof (runtime_spec_schema_config_linux_resources));

  old_len = def->linux->resources->devices_len;
  new_len = old_len;
  if (has_kvm)
    new_len += has_sev ? 2 : 1;
  if (has_awsnitro)
    new_len += 1;

  def->linux->resources->devices = xrealloc (def->linux->resources->devices, device_size * (new_len + 1));
  def->linux->resources->devices_len = new_len;

  if (has_kvm)
    {
      def->linux->resources->devices[old_len++] = make_oci_spec_dev ("a", st_kvm.st_rdev, true, "rwm");
      if (has_sev)
        def->linux->resources->devices[old_len++] = make_oci_spec_dev ("a", st_sev.st_rdev, true, "rwm");
    }

  if (has_awsnitro)
    def->linux->resources->devices[old_len++] = make_oci_spec_dev ("a", st_awsnitro.st_rdev, true, "rwm");

  return 0;
}

static int
libkrun_close_fds (void *cookie, libcrun_container_t *container, int preserve_fds, libcrun_error_t *err)
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  int first_fd_to_close = preserve_fds + 3;
  int i;

  if (kconf->use_passt && first_fd_to_close <= kconf->passt_fds[FD_PAIR_PARENT])
    {
      for (i = first_fd_to_close; i < kconf->passt_fds[FD_PAIR_PARENT]; i++)
        {
          // If we're closing proc_fd, make sure to invalidate it.
          if (i == container->proc_fd)
            container->proc_fd = -1;
          close (i);
        }

      first_fd_to_close = kconf->passt_fds[FD_PAIR_PARENT] + 1;
    }

  return mark_or_close_fds_ge_than (container, first_fd_to_close, true, err);
}

static int krun_exec_signal_fd = -1;

static void
krun_exec_signal_handler (int sig)
{
  unsigned char b = sig;
  int saved_errno = errno;

  if (krun_exec_signal_fd >= 0)
    TEMP_FAILURE_RETRY (write (krun_exec_signal_fd, &b, 1));
  errno = saved_errno;
}

/* Signals delivered to the exec helper are forwarded to the guest process; SIGWINCH
   becomes a resize of the guest terminal.  Returns the read end of the signal pipe.  */
static int
krun_exec_signal_pipe (void)
{
  static const int forwarded_signals[] = { SIGWINCH, SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, SIGUSR2 };
  struct sigaction sa;
  int sigpipe[2];
  size_t i;

  if (pipe2 (sigpipe, O_CLOEXEC | O_NONBLOCK) < 0)
    error (EXIT_FAILURE, errno, "pipe");
  krun_exec_signal_fd = sigpipe[1];

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = krun_exec_signal_handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset (&sa.sa_mask);
  for (i = 0; i < sizeof (forwarded_signals) / sizeof (forwarded_signals[0]); i++)
    sigaction (forwarded_signals[i], &sa, NULL);

  return sigpipe[0];
}

static int
libkrun_prepare_exec (void *cookie, libcrun_container_t *container, runtime_spec_schema_config_schema_process *process arg_unused, libcrun_error_t *err)
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  krun_init_controller_open_fn controller_open;
  KrunInitError init_err = NULL;

  if (! libkrun_exec_enabled (container))
    return crun_make_error (err, 0, "exec requires the container to be created with the `krun.exec=1` annotation");

  controller_open = libkrun_dlsym (kconf->handle_init, "krun_init_controller_open", err);
  if (controller_open == NULL)
    return -1;

  kconf->controller = controller_open (KRUN_STR (KRUN_CONTROL_SOCKET), KRUN_CONTROL_EXEC_TIMEOUT_MS, &init_err);
  if (init_err != NULL)
    {
      cleanup_free char *msg = libkrun_init_error_string (kconf->handle_init, init_err);
      return crun_make_error (err, 0, "could not reach the krun init control socket: %s", msg);
    }

  return 0;
}

static KrunInitExecRequest
libkrun_exec_request (void *handle_init, runtime_spec_schema_config_schema_process *process, const char *pathname, char *const argv[])
{
  KrunInitExecRequest request = KRUN_SYM (handle_init, krun_init_exec_request_new) (KRUN_STR (pathname));
  krun_init_exec_request_arg_fn add_arg = KRUN_SYM (handle_init, krun_init_exec_request_arg);
  krun_init_exec_request_env_var_fn add_env = KRUN_SYM (handle_init, krun_init_exec_request_env_var);
  size_t i;

  for (i = 0; argv[i]; i++)
    add_arg (&request, KRUN_STR (argv[i]));
  for (i = 0; environ && environ[i]; i++)
    add_env (&request, KRUN_STR (environ[i]));
  if (! is_empty_string (process->cwd))
    KRUN_SYM (handle_init, krun_init_exec_request_cwd) (&request, KRUN_STR (process->cwd));

  if (process->user)
    {
      krun_init_exec_request_additional_gid_fn add_gid = KRUN_SYM (handle_init, krun_init_exec_request_additional_gid);

      KRUN_SYM (handle_init, krun_init_exec_request_uid) (&request, process->user->uid);
      KRUN_SYM (handle_init, krun_init_exec_request_gid) (&request, process->user->gid);
      for (i = 0; i < process->user->additional_gids_len; i++)
        add_gid (&request, process->user->additional_gids[i]);
      if (process->user->umask_present)
        KRUN_SYM (handle_init, krun_init_exec_request_umask) (&request, process->user->umask);
    }

  return request;
}

static int
libkrun_exec_process (void *cookie, libcrun_container_t *container arg_unused, runtime_spec_schema_config_schema_process *process, const char *pathname, char *const argv[])
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  void *handle_init = kconf->handle_init;
  KrunInitExecRequest request;
  KrunInitProcess guest_process;
  KrunInitError init_err = NULL;
  int32_t exit_code = EXIT_FAILURE;

  if (kconf->controller == NULL)
    error (EXIT_FAILURE, 0, "krun exec: not connected to the init control socket");

  request = libkrun_exec_request (handle_init, process, pathname, argv);
  if (process->terminal)
    guest_process = KRUN_SYM (handle_init, krun_init_controller_exec_tty) (kconf->controller, request, STDIN_FILENO, &init_err);
  else
    guest_process = KRUN_SYM (handle_init, krun_init_controller_exec_pipes) (kconf->controller, request, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, &init_err);
  KRUN_SYM (handle_init, krun_init_exec_request_destroy) (request);
  if (init_err != NULL)
    {
      /* Same exit codes as a failed execve in a regular container.  */
      bool not_found = KRUN_SYM (handle_init, krun_init_error_result) (init_err) == KRUN_INIT_ERROR_CONTROL_EXECUTABLE_NOT_FOUND;

      error (not_found ? 127 : 126, 0, "krun exec: %s", libkrun_init_error_string (handle_init, init_err));
    }

  KRUN_SYM (handle_init, krun_init_process_wait) (guest_process, krun_exec_signal_pipe (), &exit_code, &init_err);
  if (init_err != NULL)
    error (EXIT_FAILURE, 0, "krun exec: %s", libkrun_init_error_string (handle_init, init_err));

  _exit (exit_code);
}

/* Deliver SIGNAL to the workload inside the VM.  Signalling the VMM process would
   only kill the VM, so route the signal through the init control socket.  SIGKILL
   still goes to the VMM, as does everything when the control socket is not
   available.  */
static int
libkrun_kill (void *cookie, libcrun_container_t *container, libcrun_container_status_t *status, int signal, libcrun_error_t *err)
{
  struct krun_config *kconf = (struct krun_config *) cookie;
  void *handle_init = kconf->handle_init;
  krun_init_controller_open_fn controller_open;
  krun_init_controller_signal_entrypoint_fn signal_entrypoint;
  krun_init_controller_destroy_fn controller_destroy;
  cleanup_free char *path = NULL;
  KrunInitController controller;
  KrunInitError init_err = NULL;
  int ret;

  libcrun_debug ("krun: kill signal %d, control socket %s", signal,
                 libkrun_exec_enabled (container) ? "enabled" : "disabled");

  if (signal == SIGKILL || ! libkrun_exec_enabled (container))
    return libcrun_kill_linux (status, signal, err);

  controller_open = libkrun_dlsym (handle_init, "krun_init_controller_open", err);
  if (controller_open == NULL)
    return -1;
  signal_entrypoint = libkrun_dlsym (handle_init, "krun_init_controller_signal_entrypoint", err);
  if (signal_entrypoint == NULL)
    return -1;
  controller_destroy = libkrun_dlsym (handle_init, "krun_init_controller_destroy", err);
  if (controller_destroy == NULL)
    return -1;

  /* The pid must still be our VMM before its /proc entry can be trusted.  */
  ret = libcrun_check_pid_valid (status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret == 0)
    {
      errno = ESRCH;
      return crun_make_error (err, errno, "kill container");
    }

  /* The socket lives in the container's /dev tmpfs, visible from the host only
     through the VMM's root.  The path also stays below the Unix socket limit.  */
  xasprintf (&path, "/proc/%d/root%s", status->pid, KRUN_CONTROL_SOCKET);

  controller = controller_open (KRUN_STR (path), KRUN_CONTROL_KILL_TIMEOUT_MS, &init_err);
  if (init_err != NULL)
    {
      cleanup_free char *msg = libkrun_init_error_string (handle_init, init_err);

      /* The guest is not up yet, so nothing in there can handle the signal anyway.  */
      libcrun_debug ("krun: control socket unavailable (%s), signalling the VMM", msg);
      return libcrun_kill_linux (status, signal, err);
    }

  signal_entrypoint (controller, signal, &init_err);
  controller_destroy (controller);
  if (init_err != NULL)
    {
      cleanup_free char *msg = libkrun_init_error_string (handle_init, init_err);
      return crun_make_error (err, 0, "krun init control: %s", msg);
    }

  return 0;
}

struct custom_handler_s handler_libkrun = {
  .name = "krun",
  .alias = NULL,
  .feature_string = "LIBKRUN",
  .supports_open_tree_namespace = false,
  .load = libkrun_load,
  .unload = libkrun_unload,
  .run_func = libkrun_exec,
  .prepare_exec = libkrun_prepare_exec,
  .exec_func = libkrun_exec_process,
  .kill_func = libkrun_kill,
  .configure_container = libkrun_configure_container,
  .modify_oci_configuration = libkrun_modify_oci_configuration,
  .close_fds = libkrun_close_fds,
};

#endif
