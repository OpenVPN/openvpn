#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static char *engine_id = "testengine";
static char *engine_name = "Engine for testing openvpn engine key support";

static int is_initialized = 0;

static int
engine_init(ENGINE *e)
{
    is_initialized = 1;
    fprintf(stderr, "ENGINE: engine_init called\n");
    return 1;
}

static int
engine_finish(ENGINE *e)
{
    fprintf(stderr, "ENGINE: engine_finsh called\n");
    is_initialized = 0;
    return 1;
}

static EVP_PKEY *
engine_load_key(ENGINE *e, const char *key_id,
                UI_METHOD *ui_method, void *cb_data)
{
    BIO *b;
    EVP_PKEY *pkey;
    PKCS8_PRIV_KEY_INFO *p8inf;
    UI *ui;
    char auth[256];

    fprintf(stderr, "ENGINE: engine_load_key called\n");

    if (!is_initialized)
    {
        fprintf(stderr, "Load Key called without correct initialization\n");
        return NULL;
    }
    b = BIO_new_file(key_id, "r");
    if (!b)
    {
        fprintf(stderr, "File %s does not exist or cannot be read\n", key_id);
        return 0;
    }
    /* Basically read an EVP_PKEY private key file with different
     * PEM guards --- we are a test engine */
    p8inf = PEM_ASN1_read_bio((d2i_of_void *)d2i_PKCS8_PRIV_KEY_INFO,
                              "TEST ENGINE KEY", b,
                              NULL, NULL, NULL);
    BIO_free(b);
    if (!p8inf)
    {
        fprintf(stderr, "Failed to read engine private key\n");
        return NULL;
    }
    pkey = EVP_PKCS82PKEY(p8inf);

    /* now we have a private key, pretend it had a password
     * this verifies the password makes it through openvpn OK */
    ui = UI_new();

    if (ui_method)
    {
        UI_set_method(ui, ui_method);
    }

    UI_add_user_data(ui, cb_data);

    if (UI_add_input_string(ui, "enter test engine key",
                            UI_INPUT_FLAG_DEFAULT_PWD,
                            auth, 0, sizeof(auth)) == 0)
    {
        fprintf(stderr, "UI_add_input_string failed\n");
        goto out;
    }

    if (UI_process(ui))
    {
        fprintf(stderr, "UI_process failed\n");
        goto out;
    }

    fprintf(stderr, "ENGINE: engine_load_key got password %s\n", auth);

out:
    UI_free(ui);

    return pkey;
}


static int
engine_bind_fn(ENGINE *e, const char *id)
{
    if (id && strcmp(id, engine_id) != 0)
    {
        return 0;
    }
    if (!ENGINE_set_id(e, engine_id)
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_init_function(e, engine_init)
        || !ENGINE_set_finish_function(e, engine_finish)
        || !ENGINE_set_load_privkey_function(e, engine_load_key))
    {
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(engine_bind_fn)
