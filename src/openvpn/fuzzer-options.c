#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "misc.h"
#include "options.h"
#include "ssl_backend.h"
#include "ssl.h"

static void serialize_options(struct options* o)
{
    test_undefined_memory(&o->gc_owned, sizeof(o->gc_owned));
    if ( o->config != NULL )
        test_undefined_memory((unsigned char*)o->config, strlen(o->config));
    test_undefined_memory(&o->mode, sizeof(o->mode));
    test_undefined_memory(&o->forward_compatible, sizeof(o->forward_compatible));
    test_undefined_memory(&o->persist_config, sizeof(o->persist_config));
    test_undefined_memory(&o->persist_mode, sizeof(o->persist_mode));
#ifdef ENABLE_CRYPTO
    if ( o->key_pass_file != NULL )
        test_undefined_memory((unsigned char*)o->key_pass_file, strlen(o->key_pass_file));
    test_undefined_memory(&o->show_ciphers, sizeof(o->show_ciphers));
    test_undefined_memory(&o->show_digests, sizeof(o->show_digests));
    test_undefined_memory(&o->show_engines, sizeof(o->show_engines));
    test_undefined_memory(&o->show_tls_ciphers, sizeof(o->show_tls_ciphers));
    test_undefined_memory(&o->show_curves, sizeof(o->show_curves));
    test_undefined_memory(&o->genkey, sizeof(o->genkey));
#endif
    test_undefined_memory(&o->connect_retry_max, sizeof(o->connect_retry_max));
    test_undefined_memory(&o->no_advance, sizeof(o->no_advance));
    test_undefined_memory(&o->unsuccessful_attempts, sizeof(o->unsuccessful_attempts));
    test_undefined_memory(&o->remote_random, sizeof(o->remote_random));
    if ( o->ipchange != NULL )
        test_undefined_memory((unsigned char*)o->ipchange, strlen(o->ipchange));
    if ( o->dev != NULL )
        test_undefined_memory((unsigned char*)o->dev, strlen(o->dev));
    if ( o->dev_type != NULL )
        test_undefined_memory((unsigned char*)o->dev_type, strlen(o->dev_type));
    if ( o->dev_node != NULL )
        test_undefined_memory((unsigned char*)o->dev_node, strlen(o->dev_node));
    if ( o->lladdr != NULL )
        test_undefined_memory((unsigned char*)o->lladdr, strlen(o->lladdr));
    if ( o->ifconfig_local != NULL )
        test_undefined_memory((unsigned char*)o->ifconfig_local, strlen(o->ifconfig_local));
    if ( o->ifconfig_remote_netmask != NULL )
        test_undefined_memory((unsigned char*)o->ifconfig_remote_netmask, strlen(o->ifconfig_remote_netmask));
    if ( o->ifconfig_ipv6_local != NULL )
        test_undefined_memory((unsigned char*)o->ifconfig_ipv6_local, strlen(o->ifconfig_ipv6_local));
    test_undefined_memory(&o->ifconfig_ipv6_netbits, sizeof(o->ifconfig_ipv6_netbits));
    if ( o->ifconfig_ipv6_remote != NULL )
        test_undefined_memory((unsigned char*)o->ifconfig_ipv6_remote, strlen(o->ifconfig_ipv6_remote));
    test_undefined_memory(&o->ifconfig_noexec, sizeof(o->ifconfig_noexec));
    test_undefined_memory(&o->ifconfig_nowarn, sizeof(o->ifconfig_nowarn));
#ifdef ENABLE_FEATURE_SHAPER
    test_undefined_memory(&o->shaper, sizeof(o->shaper));
#endif
    test_undefined_memory(&o->proto_force, sizeof(o->proto_force));
#ifdef ENABLE_OCC
    test_undefined_memory(&o->mtu_test, sizeof(o->mtu_test));
#endif
#ifdef ENABLE_MEMSTATS
    if ( o->memstats_fn != NULL )
        test_undefined_memory((unsigned char*)o->memstats_fn, strlen(o->memstats_fn));
#endif
    test_undefined_memory(&o->mlock, sizeof(o->mlock));
    test_undefined_memory(&o->keepalive_timeout, sizeof(o->keepalive_timeout));
    test_undefined_memory(&o->inactivity_minimum_bytes, sizeof(o->inactivity_minimum_bytes));
#if PASSTOS_CAPABILITY
    test_undefined_memory(&o->passtos, sizeof(o->passtos));
#endif
    test_undefined_memory(&o->resolve_in_advance, sizeof(o->resolve_in_advance));
    if ( o->ip_remote_hint != NULL )
        test_undefined_memory((unsigned char*)o->ip_remote_hint, strlen(o->ip_remote_hint));
    if ( o->username != NULL )
        test_undefined_memory((unsigned char*)o->username, strlen(o->username));
    if ( o->groupname != NULL )
        test_undefined_memory((unsigned char*)o->groupname, strlen(o->groupname));
    if ( o->chroot_dir != NULL )
        test_undefined_memory((unsigned char*)o->chroot_dir, strlen(o->chroot_dir));
    if ( o->cd_dir != NULL )
        test_undefined_memory((unsigned char*)o->cd_dir, strlen(o->cd_dir));
#ifdef ENABLE_SELINUX
    if ( o->selinux_context != NULL )
        test_undefined_memory((unsigned char*)o->selinux_context, strlen(o->selinux_context));
#endif
    if ( o->writepid != NULL )
        test_undefined_memory((unsigned char*)o->writepid, strlen(o->writepid));
    if ( o->up_script != NULL )
        test_undefined_memory((unsigned char*)o->up_script, strlen(o->up_script));
    if ( o->down_script != NULL )
        test_undefined_memory((unsigned char*)o->down_script, strlen(o->down_script));
    test_undefined_memory(&o->user_script_used, sizeof(o->user_script_used));
    test_undefined_memory(&o->down_pre, sizeof(o->down_pre));
    test_undefined_memory(&o->up_delay, sizeof(o->up_delay));
    test_undefined_memory(&o->up_restart, sizeof(o->up_restart));
    test_undefined_memory(&o->daemon, sizeof(o->daemon));
    test_undefined_memory(&o->remap_sigusr1, sizeof(o->remap_sigusr1));
    test_undefined_memory(&o->inetd, sizeof(o->inetd));
    test_undefined_memory(&o->log, sizeof(o->log));
    test_undefined_memory(&o->suppress_timestamps, sizeof(o->suppress_timestamps));
    test_undefined_memory(&o->machine_readable_output, sizeof(o->machine_readable_output));
    test_undefined_memory(&o->nice, sizeof(o->nice));
    test_undefined_memory(&o->verbosity, sizeof(o->verbosity));
    test_undefined_memory(&o->mute, sizeof(o->mute));
#ifdef ENABLE_DEBUG
    test_undefined_memory(&o->gremlin, sizeof(o->gremlin));
#endif
    if ( o->status_file != NULL )
        test_undefined_memory((unsigned char*)o->status_file, strlen(o->status_file));
    test_undefined_memory(&o->status_file_version, sizeof(o->status_file_version));
    test_undefined_memory(&o->status_file_update_freq, sizeof(o->status_file_update_freq));
    test_undefined_memory(&o->fast_io, sizeof(o->fast_io));
#ifdef USE_COMP
#endif
    test_undefined_memory(&o->rcvbuf, sizeof(o->rcvbuf));
    test_undefined_memory(&o->sndbuf, sizeof(o->sndbuf));
    test_undefined_memory(&o->mark, sizeof(o->mark));
    test_undefined_memory(&o->sockflags, sizeof(o->sockflags));
    if ( o->route_script != NULL )
        test_undefined_memory((unsigned char*)o->route_script, strlen(o->route_script));
    if ( o->route_predown_script != NULL )
        test_undefined_memory((unsigned char*)o->route_predown_script, strlen(o->route_predown_script));
    if ( o->route_default_gateway != NULL )
        test_undefined_memory((unsigned char*)o->route_default_gateway, strlen(o->route_default_gateway));
    test_undefined_memory(&o->route_default_metric, sizeof(o->route_default_metric));
    test_undefined_memory(&o->route_noexec, sizeof(o->route_noexec));
    test_undefined_memory(&o->route_delay, sizeof(o->route_delay));
    test_undefined_memory(&o->route_delay_window, sizeof(o->route_delay_window));
    test_undefined_memory(&o->route_delay_defined, sizeof(o->route_delay_defined));
    test_undefined_memory(&o->route_nopull, sizeof(o->route_nopull));
    test_undefined_memory(&o->route_gateway_via_dhcp, sizeof(o->route_gateway_via_dhcp));
#ifdef ENABLE_OCC
    test_undefined_memory(&o->occ, sizeof(o->occ));
#endif
#ifdef ENABLE_MANAGEMENT
    if ( o->management_addr != NULL )
        test_undefined_memory((unsigned char*)o->management_addr, strlen(o->management_addr));
    if ( o->management_port != NULL )
        test_undefined_memory((unsigned char*)o->management_port, strlen(o->management_port));
    if ( o->management_user_pass != NULL )
        test_undefined_memory((unsigned char*)o->management_user_pass, strlen(o->management_user_pass));
    test_undefined_memory(&o->management_log_history_cache, sizeof(o->management_log_history_cache));
    test_undefined_memory(&o->management_echo_buffer_size, sizeof(o->management_echo_buffer_size));
    test_undefined_memory(&o->management_state_buffer_size, sizeof(o->management_state_buffer_size));
    if ( o->management_write_peer_info_file != NULL )
        test_undefined_memory((unsigned char*)o->management_write_peer_info_file, strlen(o->management_write_peer_info_file));
    if ( o->management_client_user != NULL )
        test_undefined_memory((unsigned char*)o->management_client_user, strlen(o->management_client_user));
    if ( o->management_client_group != NULL )
        test_undefined_memory((unsigned char*)o->management_client_group, strlen(o->management_client_group));
    test_undefined_memory(&o->management_flags, sizeof(o->management_flags));
    if ( o->management_certificate != NULL )
        test_undefined_memory((unsigned char*)o->management_certificate, strlen(o->management_certificate));
#endif
#if P2MP
#if P2MP_SERVER
    if ( o->tmp_dir != NULL )
        test_undefined_memory((unsigned char*)o->tmp_dir, strlen(o->tmp_dir));
    test_undefined_memory(&o->server_defined, sizeof(o->server_defined));
    test_undefined_memory(&o->server_network, sizeof(o->server_network));
    test_undefined_memory(&o->server_netmask, sizeof(o->server_netmask));
    test_undefined_memory(&o->server_flags, sizeof(o->server_flags));
    test_undefined_memory(&o->server_bridge_proxy_dhcp, sizeof(o->server_bridge_proxy_dhcp));
    test_undefined_memory(&o->server_bridge_defined, sizeof(o->server_bridge_defined));
    test_undefined_memory(&o->server_bridge_ip, sizeof(o->server_bridge_ip));
    test_undefined_memory(&o->server_bridge_netmask, sizeof(o->server_bridge_netmask));
    test_undefined_memory(&o->server_bridge_pool_start, sizeof(o->server_bridge_pool_start));
    test_undefined_memory(&o->server_bridge_pool_end, sizeof(o->server_bridge_pool_end));
    test_undefined_memory(&o->ifconfig_pool_defined, sizeof(o->ifconfig_pool_defined));
    test_undefined_memory(&o->ifconfig_pool_start, sizeof(o->ifconfig_pool_start));
    test_undefined_memory(&o->ifconfig_pool_end, sizeof(o->ifconfig_pool_end));
    test_undefined_memory(&o->ifconfig_pool_netmask, sizeof(o->ifconfig_pool_netmask));
    if ( o->ifconfig_pool_persist_filename != NULL )
        test_undefined_memory((unsigned char*)o->ifconfig_pool_persist_filename, strlen(o->ifconfig_pool_persist_filename));
    test_undefined_memory(&o->ifconfig_pool_persist_refresh_freq, sizeof(o->ifconfig_pool_persist_refresh_freq));
    test_undefined_memory(&o->real_hash_size, sizeof(o->real_hash_size));
    test_undefined_memory(&o->virtual_hash_size, sizeof(o->virtual_hash_size));
    if ( o->client_connect_script != NULL )
        test_undefined_memory((unsigned char*)o->client_connect_script, strlen(o->client_connect_script));
    if ( o->client_disconnect_script != NULL )
        test_undefined_memory((unsigned char*)o->client_disconnect_script, strlen(o->client_disconnect_script));
    if ( o->learn_address_script != NULL )
        test_undefined_memory((unsigned char*)o->learn_address_script, strlen(o->learn_address_script));
    if ( o->client_config_dir != NULL )
        test_undefined_memory((unsigned char*)o->client_config_dir, strlen(o->client_config_dir));
    test_undefined_memory(&o->ccd_exclusive, sizeof(o->ccd_exclusive));
    test_undefined_memory(&o->disable, sizeof(o->disable));
    test_undefined_memory(&o->n_bcast_buf, sizeof(o->n_bcast_buf));
    test_undefined_memory(&o->tcp_queue_limit, sizeof(o->tcp_queue_limit));
    test_undefined_memory(&o->push_ifconfig_defined, sizeof(o->push_ifconfig_defined));
    test_undefined_memory(&o->push_ifconfig_local, sizeof(o->push_ifconfig_local));
    test_undefined_memory(&o->push_ifconfig_remote_netmask, sizeof(o->push_ifconfig_remote_netmask));
    test_undefined_memory(&o->push_ifconfig_local_alias, sizeof(o->push_ifconfig_local_alias));
    test_undefined_memory(&o->push_ifconfig_constraint_defined, sizeof(o->push_ifconfig_constraint_defined));
    test_undefined_memory(&o->push_ifconfig_constraint_network, sizeof(o->push_ifconfig_constraint_network));
    test_undefined_memory(&o->push_ifconfig_constraint_netmask, sizeof(o->push_ifconfig_constraint_netmask));
    test_undefined_memory(&o->enable_c2c, sizeof(o->enable_c2c));
    test_undefined_memory(&o->duplicate_cn, sizeof(o->duplicate_cn));
    test_undefined_memory(&o->cf_max, sizeof(o->cf_max));
    test_undefined_memory(&o->cf_per, sizeof(o->cf_per));
    test_undefined_memory(&o->max_clients, sizeof(o->max_clients));
    test_undefined_memory(&o->max_routes_per_client, sizeof(o->max_routes_per_client));
    test_undefined_memory(&o->stale_routes_check_interval, sizeof(o->stale_routes_check_interval));
    test_undefined_memory(&o->stale_routes_ageing_time, sizeof(o->stale_routes_ageing_time));
    if ( o->auth_user_pass_verify_script != NULL )
        test_undefined_memory((unsigned char*)o->auth_user_pass_verify_script, strlen(o->auth_user_pass_verify_script));
    test_undefined_memory(&o->auth_user_pass_verify_script_via_file, sizeof(o->auth_user_pass_verify_script_via_file));
    test_undefined_memory(&o->auth_token_generate, sizeof(o->auth_token_generate));
    test_undefined_memory(&o->auth_token_lifetime, sizeof(o->auth_token_lifetime));
#if PORT_SHARE
    if ( o->port_share_host != NULL )
        test_undefined_memory((unsigned char*)o->port_share_host, strlen(o->port_share_host));
    if ( o->port_share_port != NULL )
        test_undefined_memory((unsigned char*)o->port_share_port, strlen(o->port_share_port));
    if ( o->port_share_journal_dir != NULL )
        test_undefined_memory((unsigned char*)o->port_share_journal_dir, strlen(o->port_share_journal_dir));
#endif
#endif
    test_undefined_memory(&o->client, sizeof(o->client));
    test_undefined_memory(&o->push_continuation, sizeof(o->push_continuation));
    test_undefined_memory(&o->push_option_types_found, sizeof(o->push_option_types_found));
    if ( o->auth_user_pass_file != NULL )
        test_undefined_memory((unsigned char*)o->auth_user_pass_file, strlen(o->auth_user_pass_file));
    test_undefined_memory(&o->scheduled_exit_interval, sizeof(o->scheduled_exit_interval));
#endif
#ifdef ENABLE_CRYPTO
    if ( o->shared_secret_file != NULL )
        test_undefined_memory((unsigned char*)o->shared_secret_file, strlen(o->shared_secret_file));
    if ( o->shared_secret_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->shared_secret_file_inline, strlen(o->shared_secret_file_inline));
    test_undefined_memory(&o->key_direction, sizeof(o->key_direction));
    if ( o->ciphername != NULL )
        test_undefined_memory((unsigned char*)o->ciphername, strlen(o->ciphername));
    test_undefined_memory(&o->ncp_enabled, sizeof(o->ncp_enabled));
    if ( o->ncp_ciphers != NULL )
        test_undefined_memory((unsigned char*)o->ncp_ciphers, strlen(o->ncp_ciphers));
    if ( o->authname != NULL )
        test_undefined_memory((unsigned char*)o->authname, strlen(o->authname));
    test_undefined_memory(&o->keysize, sizeof(o->keysize));
    if ( o->prng_hash != NULL )
        test_undefined_memory((unsigned char*)o->prng_hash, strlen(o->prng_hash));
    test_undefined_memory(&o->prng_nonce_secret_len, sizeof(o->prng_nonce_secret_len));
    if ( o->engine != NULL )
        test_undefined_memory((unsigned char*)o->engine, strlen(o->engine));
    test_undefined_memory(&o->replay, sizeof(o->replay));
    test_undefined_memory(&o->mute_replay_warnings, sizeof(o->mute_replay_warnings));
    test_undefined_memory(&o->replay_window, sizeof(o->replay_window));
    test_undefined_memory(&o->replay_time, sizeof(o->replay_time));
    if ( o->packet_id_file != NULL )
        test_undefined_memory((unsigned char*)o->packet_id_file, strlen(o->packet_id_file));
    test_undefined_memory(&o->test_crypto, sizeof(o->test_crypto));
#ifdef ENABLE_PREDICTION_RESISTANCE
    test_undefined_memory(&o->use_prediction_resistance, sizeof(o->use_prediction_resistance));
#endif
    test_undefined_memory(&o->tls_server, sizeof(o->tls_server));
    test_undefined_memory(&o->tls_client, sizeof(o->tls_client));
    if ( o->ca_file != NULL )
        test_undefined_memory((unsigned char*)o->ca_file, strlen(o->ca_file));
    if ( o->ca_path != NULL )
        test_undefined_memory((unsigned char*)o->ca_path, strlen(o->ca_path));
    if ( o->dh_file != NULL )
        test_undefined_memory((unsigned char*)o->dh_file, strlen(o->dh_file));
    if ( o->cert_file != NULL )
        test_undefined_memory((unsigned char*)o->cert_file, strlen(o->cert_file));
    if ( o->extra_certs_file != NULL )
        test_undefined_memory((unsigned char*)o->extra_certs_file, strlen(o->extra_certs_file));
    if ( o->priv_key_file != NULL )
        test_undefined_memory((unsigned char*)o->priv_key_file, strlen(o->priv_key_file));
    if ( o->pkcs12_file != NULL )
        test_undefined_memory((unsigned char*)o->pkcs12_file, strlen(o->pkcs12_file));
    if ( o->cipher_list != NULL )
        test_undefined_memory((unsigned char*)o->cipher_list, strlen(o->cipher_list));
    if ( o->ecdh_curve != NULL )
        test_undefined_memory((unsigned char*)o->ecdh_curve, strlen(o->ecdh_curve));
    if ( o->tls_verify != NULL )
        test_undefined_memory((unsigned char*)o->tls_verify, strlen(o->tls_verify));
    test_undefined_memory(&o->verify_x509_type, sizeof(o->verify_x509_type));
    if ( o->verify_x509_name != NULL )
        test_undefined_memory((unsigned char*)o->verify_x509_name, strlen(o->verify_x509_name));
    if ( o->tls_export_cert != NULL )
        test_undefined_memory((unsigned char*)o->tls_export_cert, strlen(o->tls_export_cert));
    if ( o->crl_file != NULL )
        test_undefined_memory((unsigned char*)o->crl_file, strlen(o->crl_file));
    if ( o->ca_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->ca_file_inline, strlen(o->ca_file_inline));
    if ( o->cert_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->cert_file_inline, strlen(o->cert_file_inline));
    if ( o->extra_certs_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->extra_certs_file_inline, strlen(o->extra_certs_file_inline));
    if ( o->crl_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->crl_file_inline, strlen(o->crl_file_inline));
    if ( o->priv_key_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->priv_key_file_inline, strlen(o->priv_key_file_inline));
    if ( o->dh_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->dh_file_inline, strlen(o->dh_file_inline));
    if ( o->remote_cert_eku != NULL )
        test_undefined_memory((unsigned char*)o->remote_cert_eku, strlen(o->remote_cert_eku));
    test_undefined_memory(&o->verify_hash_algo, sizeof(o->verify_hash_algo));
#ifdef ENABLE_PKCS11
    test_undefined_memory(&o->pkcs11_pin_cache_period, sizeof(o->pkcs11_pin_cache_period));
    if ( o->pkcs11_id != NULL )
        test_undefined_memory((unsigned char*)o->pkcs11_id, strlen(o->pkcs11_id));
    test_undefined_memory(&o->pkcs11_id_management, sizeof(o->pkcs11_id_management));
#endif
#ifdef ENABLE_CRYPTOAPI
    if ( o->cryptoapi_cert != NULL )
        test_undefined_memory((unsigned char*)o->cryptoapi_cert, strlen(o->cryptoapi_cert));
#endif
    test_undefined_memory(&o->key_method, sizeof(o->key_method));
    test_undefined_memory(&o->tls_timeout, sizeof(o->tls_timeout));
    test_undefined_memory(&o->renegotiate_bytes, sizeof(o->renegotiate_bytes));
    test_undefined_memory(&o->renegotiate_packets, sizeof(o->renegotiate_packets));
    test_undefined_memory(&o->renegotiate_seconds, sizeof(o->renegotiate_seconds));
    test_undefined_memory(&o->handshake_window, sizeof(o->handshake_window));
#ifdef ENABLE_X509ALTUSERNAME
    if ( o->x509_username_field != NULL )
        test_undefined_memory((unsigned char*)o->x509_username_field, strlen(o->x509_username_field));
#endif
    test_undefined_memory(&o->transition_window, sizeof(o->transition_window));
    if ( o->tls_auth_file != NULL )
        test_undefined_memory((unsigned char*)o->tls_auth_file, strlen(o->tls_auth_file));
    if ( o->tls_auth_file_inline != NULL )
        test_undefined_memory((unsigned char*)o->tls_auth_file_inline, strlen(o->tls_auth_file_inline));
    if ( o->tls_crypt_file != NULL )
        test_undefined_memory((unsigned char*)o->tls_crypt_file, strlen(o->tls_crypt_file));
    if ( o->tls_crypt_inline != NULL )
        test_undefined_memory((unsigned char*)o->tls_crypt_inline, strlen(o->tls_crypt_inline));
    test_undefined_memory(&o->single_session, sizeof(o->single_session));
#ifdef ENABLE_PUSH_PEER_INFO
    test_undefined_memory(&o->push_peer_info, sizeof(o->push_peer_info));
#endif
    test_undefined_memory(&o->tls_exit, sizeof(o->tls_exit));
#endif
    test_undefined_memory(&o->foreign_option_index, sizeof(o->foreign_option_index));
    test_undefined_memory(&o->use_peer_id, sizeof(o->use_peer_id));
    test_undefined_memory(&o->peer_id, sizeof(o->peer_id));
#if defined(ENABLE_CRYPTO_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10001000
    if ( o->keying_material_exporter_label != NULL )
        test_undefined_memory((unsigned char*)o->keying_material_exporter_label, strlen(o->keying_material_exporter_label));
    test_undefined_memory(&o->keying_material_exporter_length, sizeof(o->keying_material_exporter_length));
#endif
    test_undefined_memory(&o->allow_recursive_routing, sizeof(o->allow_recursive_routing));
}
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct gc_arena gc;
    struct env_set* es;
    struct options options;
    memset(&options, 0, sizeof(options));
    char* config;
    unsigned int permission_mask, option_types_found;

    if ( size < sizeof(permission_mask) + 512 )
    {
        return 0;
    }
    memcpy(&permission_mask, data, sizeof(permission_mask));
    data += sizeof(permission_mask);
    size -= sizeof(permission_mask);

    config = malloc(512+1);
    memcpy(config, data, 512);
    config[512] = 0;

    data += 512;
    size -= 512;

    fuzzer_set_input((unsigned char*)data, size);

    options.gc = gc_new();
    es = env_set_create(&options.gc);

    options_string_import(
            &options,
            config,
            0,
            permission_mask,
            &option_types_found,
            es);
#ifdef MSAN
    serialize_options(&options);
#endif
#if 0
#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_OPENSSL)
    tls_ctx_restrict_ciphers(NULL, options.cipher_list);
#endif
    if ( options.ciphername && options.ncp_ciphers )
    {
        tls_item_in_cipher_list(options.ciphername, options.ncp_ciphers);
    }
#endif
    getaddrinfo_free_all();
    free(config);
    gc_free(&options.gc);
    return 0;
}
#endif /* FUZZING */
