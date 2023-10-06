#if defined(DM_PLATFORM_LINUX)

/*
  Native File Dialog

  http://www.frogtoss.com/labs
*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <dbus/dbus.h>
#include <dmsdk/graphics/graphics_native.h>
#include "nfd.h"
#include "nfd_common.h"

#define SIMPLE_EXEC_IMPLEMENTATION
#include "simple_exec.h"

const char NO_ZENITY_MSG[] = "zenity not installed";

static char *get_parent_window()
{
    char *id_str = (char *)NFDi_Malloc(4 + 8 + 1); // "x11:" + xid + null
    unsigned long xid = dmGraphics::GetNativeX11Window();
    sprintf(id_str, "x11:%08lx", xid);
    return id_str;
}

DBusConnection *CONNECTION;
static nfdresult_t init_dbus(DBusConnection **connection)
{
    DBusError error;
    dbus_error_init(&error);

    *connection = dbus_bus_get(DBUS_BUS_SESSION, &error);
    if (dbus_error_is_set(&error))
    {
        NFDi_SetError(error.message);
        return NFD_ERROR;
    }

    DBusError add_match_error;
    dbus_bus_add_match(CONNECTION, "type='signal',interface='org.freedesktop.portal.Request'", &add_match_error);

    return NFD_OKAY;
}

static nfdresult_t ensure_dbus_connection()
{
    if (!CONNECTION)
    {
        return init_dbus(&CONNECTION);
    }
    return NFD_OKAY;
}

void append_variant(DBusMessageIter *iter, const char *type, const void *value)
{
    DBusMessageIter variant;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, type, &variant);
    dbus_message_iter_append_basic(&variant, type[0], value);
    dbus_message_iter_close_container(iter, &variant);
}

void append_vardict_entry(DBusMessageIter *iter, int key_type, int value_type, const void *key, const void *value)
{
    DBusMessageIter dict_entry;
    dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_entry);
    dbus_message_iter_append_basic(&dict_entry, key_type, key);

    char type[2];
    type[0] = value_type;
    type[1] = '\0';
    append_variant(&dict_entry, type, value);

    dbus_message_iter_close_container(iter, &dict_entry);
}

void send_message(DBusConnection *connection, DBusMessage *message)
{
    DBusError error;
    dbus_error_init(&error);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(connection, message, DBUS_TIMEOUT_USE_DEFAULT, &error);
    dbus_connection_flush(connection);
    dbus_message_unref(message);
}

DBusMessageIter init_open_file_args(DBusMessage *message)
{
    const char *parent_window = get_parent_window();
    const char *window_title = "Open File";

    DBusMessageIter args;
    dbus_message_iter_init_append(message, &args);
    dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &parent_window); // https://flatpak.github.io/xdg-desktop-portal/#parent_window
    dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &window_title);  // Window title

    return args;
}

DBusMessageIter init_options(DBusMessageIter *args)
{
    DBusMessageIter options;
    dbus_message_iter_open_container(args, DBUS_TYPE_ARRAY, "{sv}", &options);

    return options;
}

nfdresult_t check_response_message_args(DBusMessageIter *args)
{
    if (dbus_message_iter_get_arg_type(args) != DBUS_TYPE_UINT32)
    {
        return NFD_ERROR;
    }

    uint32_t response_code;
    dbus_message_iter_get_basic(args, &response_code);

    if (response_code > 0)
    {
        return NFD_CANCEL;
    }

    dbus_message_iter_next(args);

    if (dbus_message_iter_get_arg_type(args) != DBUS_TYPE_ARRAY)
    {
        return NFD_ERROR;
    }

    return NFD_OKAY;
}

bool check_type_and_recurse(DBusMessageIter *iter, int arg_type, DBusMessageIter *sub_iter)
{
    if (dbus_message_iter_get_arg_type(iter) == arg_type)
    {
        dbus_message_iter_recurse(iter, sub_iter);
        return true;
    }
    return false;
}

nfdresult_t parse_response_message(DBusMessage *message, nfdpathset_t *path_set)
{
    DBusMessageIter args;
    dbus_message_iter_init(message, &args);

    nfdresult_t args_result = check_response_message_args(&args);
    if (args_result != NFD_OKAY)
        return args_result;

    DBusMessageIter response;
    dbus_message_iter_recurse(&args, &response);

    while (dbus_message_iter_get_arg_type(&response) == DBUS_TYPE_DICT_ENTRY)
    {
        DBusMessageIter dict_iter;
        dbus_message_iter_recurse(&response, &dict_iter);

        const char *key;
        dbus_message_iter_get_basic(&dict_iter, &key);

        if (strcmp(key, "uris") == 0)
        {
            dbus_message_iter_next(&dict_iter);

            DBusMessageIter variant_iter;
            if (check_type_and_recurse(&dict_iter, DBUS_TYPE_VARIANT, &variant_iter))
            {
                DBusMessageIter uris_iter;
                if (check_type_and_recurse(&variant_iter, DBUS_TYPE_ARRAY, &uris_iter))
                {
                    path_set->count = dbus_message_iter_get_element_count(&variant_iter);
                    char *uris[path_set->count];

                    int i = 0;
                    size_t path_buf_size = 0;
                    while (dbus_message_iter_get_arg_type(&uris_iter) == DBUS_TYPE_STRING)
                    {
                        const char *uri;
                        dbus_message_iter_get_basic(&uris_iter, &uri);

                        uris[i] = strdup(uri);

                        path_buf_size += strlen(uris[i]) + 1;

                        dbus_message_iter_next(&uris_iter);
                        i++;
                    }

                    path_set->buf = (char *)NFDi_Malloc(path_buf_size);
                    path_set->indices = (size_t *)NFDi_Malloc(sizeof(size_t) * path_set->count);

                    size_t bytes_copied = 0;
                    for (int i = 0; i < path_set->count; i++)
                    {
                        strcpy(&path_set->buf[bytes_copied], uris[i]);
                        path_set->indices[i] = bytes_copied;

                        bytes_copied += strlen(uris[i]) + 1;
                    }

                    assert(bytes_copied == path_buf_size);
                }
            }
        }
        dbus_message_iter_next(&response);
    }

    return NFD_OKAY;
}

DBusMessage *new_open_file_message()
{
    return dbus_message_new_method_call(
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.FileChooser",
        "OpenFile");
}

void set_handle_token(DBusMessageIter *options)
{
    const char *handle_token_key = "handle_token";
    const char *handle_token = "DefDiags";

    append_vardict_entry(options, DBUS_TYPE_STRING, DBUS_TYPE_STRING, &handle_token_key, &handle_token);
}

void set_multiple(DBusMessageIter *options, bool multiple)
{
    const char *key = "multiple";
    append_vardict_entry(options, DBUS_TYPE_STRING, DBUS_TYPE_BOOLEAN, &key, &multiple);
}

void set_directory(DBusMessageIter *options, bool directory)
{
    const char *key = "directory";
    append_vardict_entry(options, DBUS_TYPE_STRING, DBUS_TYPE_BOOLEAN, &key, &directory);
}

size_t filter_count(const char *filters)
{
    const char *current_char = filters;
    int filter_count = 1;
    while (current_char)
    {
        if (*current_char == ';')
        {
            filter_count++;
        }
        current_char++;
    }

    return filter_count;
}

void split_filters(const char *filters)
{
    size_t count = filter_count(filters);
    size_t current_filter = 0;
    const char *current_char = filters;
    const char *filter_array[count];
    while (current_char)
    {
        }
}

nfdresult_t set_filters(DBusMessageIter *options, const char *filters)
{
    if (!filters || strlen(filters) == 0)
    {
        return NFD_OKAY;
    }

    const char *key = "filters";
    DBusMessageIter dict_entry;
    dbus_message_iter_open_container(options, DBUS_TYPE_DICT_ENTRY, NULL, &dict_entry);
    dbus_message_iter_append_basic(&dict_entry, DBUS_TYPE_STRING, &key);

    DBusMessageIter filters_array;
    dbus_message_iter_open_container(&dict_entry, DBUS_TYPE_ARRAY, "(sa(us))", &filters_array);

    char current_filter_name[NFD_MAX_STRLEN] = {0};
    const char *current_char = filters;
    while (*current_char)
    {

        current_char++;
    }

    dbus_message_iter_close_container(&dict_entry, &filters_array);
    dbus_message_iter_close_container(options, &dict_entry);
}

nfdresult_t dbus(bool multiple, bool directory, const char *filters, const nfdchar_t *default_path, nfdpathset_t *out_path_set)
{
    if (ensure_dbus_connection() == NFD_ERROR)
    {
        return NFD_ERROR;
    }

    DBusMessage *message = new_open_file_message();
    DBusMessageIter args = init_open_file_args(message);

    // Options
    DBusMessageIter options = init_options(&args);
    set_handle_token(&options);
    set_multiple(&options, multiple);
    set_directory(&options, directory);
    set_filters(&options, filters);
    dbus_message_iter_close_container(&args, &options);

    send_message(CONNECTION, message);

    while (1)
    {
        if (!dbus_connection_read_write(CONNECTION, 1000))
        {
            // Connection closed
            return NFD_ERROR;
        }

        DBusMessage *response = dbus_connection_pop_message(CONNECTION);

        if (response == NULL)
        {
            continue;
        }

        if (!dbus_message_is_signal(response, "org.freedesktop.portal.Request", "Response"))
        {
            // Not the message you're looking for
            dbus_message_unref(response);
            continue;
        }

        nfdresult_t result = parse_response_message(response, out_path_set);
        if (result != NFD_OKAY)
        {
            return result;
        }

        // If this happens, something has gone very wrong
        if (out_path_set->count == 0)
        {
            return NFD_ERROR;
        }

        dbus_message_unref(response);

        break;
    }

    return NFD_OKAY;
}

/* public */

nfdresult_t NFD_OpenDialog(const char *filterList,
                           const nfdchar_t *defaultPath,
                           nfdchar_t **outPath)
{
    nfdpathset_t path_set;
    nfdresult_t result = dbus(false, false, filterList, defaultPath, &path_set);

    if (result != NFD_OKAY)
    {
        return result;
    }

    *outPath = strdup(&path_set.buf[0]);
    return NFD_OKAY;
}

nfdresult_t NFD_OpenDialogMultiple(const nfdchar_t *filterList,
                                   const nfdchar_t *defaultPath,
                                   nfdpathset_t *outPaths)
{
    return dbus(true, false, filterList, defaultPath, outPaths);
}

nfdresult_t NFD_SaveDialog(const nfdchar_t *filterList,
                           const nfdchar_t *defaultPath,
                           nfdchar_t **outPath)
{
    int commandLen = 100;
    char *command[commandLen];
    memset(command, 0, commandLen * sizeof(char *));

    command[0] = strdup("zenity");
    command[1] = strdup("--file-selection");
    command[2] = strdup("--title=Save File");
    command[3] = strdup("--save");

    char *stdOut = NULL;
    nfdresult_t result = ZenityCommon(command, commandLen, defaultPath, filterList, &stdOut);

    if (stdOut != NULL)
    {
        size_t len = strlen(stdOut);
        *outPath = (char *)NFDi_Malloc(len);
        memcpy(*outPath, stdOut, len);
        (*outPath)[len - 1] = '\0'; // trim out the final \n with a null terminator
        free(stdOut);
    }
    else
    {
        *outPath = NULL;
    }

    return result;
}

nfdresult_t NFD_PickFolder(const nfdchar_t *defaultPath,
                           nfdchar_t **outPath)
{
    nfdpathset_t path_set;
    nfdresult_t result = dbus(false, true, NULL, defaultPath, &path_set);

    if (result != NFD_OKAY)
    {
        return result;
    }

    *outPath = strdup(&path_set.buf[0]);
    return NFD_OKAY;
}
#endif
