#include <glib.h>
#include <stdlib.h>

static gchar *conffile = NULL;

static GOptionEntry entires[] = {
    {"config", 'c', 0, G_OPTION_ARG_FILENAME, &conffile, "config file path", NULL},
    {NULL, 0, 0, 0, 0 , NULL, NULL}
};

int main(int argc, char *argv[]) {
    GError *error = NULL;
    GOptionContext *optctx = g_option_context_new("testing options");

    g_option_context_add_main_entries(optctx, entires, NULL);
    //g_option_context_add_group();
    if (!g_option_context_parse(optctx, &argc, &argv, &error)) {
        g_print("option parsing failed: %s\n", error->message);
        exit(1);
    }
    g_print("config file: %s\n", conffile);
    return 0;
}
