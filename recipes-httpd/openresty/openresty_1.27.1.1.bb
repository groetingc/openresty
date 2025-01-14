SUMMARY = "OpenResty - Web Server with Nginx, LuaJIT, and other modules"
DESCRIPTION = "OpenResty is a full-fledged web platform based on Nginx, LuaJIT, and several other powerful Lua libraries."
HOMEPAGE = "https://openresty.org/"
LICENSE = "BSD-2-Clause"
LIC_FILES_CHKSUM = "file://COPYRIGHT;md5=31e7ea1b91f96208b28b22fb4bc38b32"

SRC_URI = "https://openresty.org/download/openresty-${PV}.tar.gz"
SRC_URI += "file://luajit_build_cc.patch"

# taken from meta-openembedded/meta-webserver/recipes-httpd/nginx/files
# renamed to _patch in order to avoid do_patch function tries to apply these patch files automatically
SRC_URI += "file://nginx-cross_patch"
SRC_URI += "file://configure-libxslt-conf_patch"
SRC_URI += "file://Allow-the-overriding-of-the-endianness-via-the-confi_patch"


NGINX_VERSION = "1.27.1"

SRC_URI[md5sum] = "d76bef379280fb6cee2826205b12b9b6"
SRC_URI[sha256sum] = "79b071e27bdc143d5f401d0dbf504de4420070d867538c5edc2546d0351fd5c0"

inherit autotools-brokensep

DEPENDS = "libpcre openssl zlib ldconfig-native virtual/crypt"

# taken from meta-openembedded/meta-webserver/recipes-httpd/nginx/nginx.inc
CFLAGS:append = " -fPIE -pie"
CXXFLAGS:append = " -fPIE -pie"
EXTRA_OECONF = ""
DISABLE_STATIC = ""

# tune openresty config to be optimized for embedded devices (no mysql,redis)
EXTRA_OECONF = "--with-luajit --with-pcre  --with-cc='${CC}'"
EXTRA_OECONF += " \
                --without-http_redis2_module \
                --with-http_iconv_module \
                --without-lua_resty_redis \
                --without-lua_resty_mysql \
                "

# taken from meta-openembedded/meta-oe/recipes-devtools/luajit/luajit_git.bb
BUILD_CC_ARCH:append = " ${@['-m32',''][d.getVar('SITEINFO_BITS') != '32']}"

# manually apply patches taken from meta-openembedded/meta-webserver/recipes-httpd/nginx/files 
do_configure:prepend () {
    cp ${WORKDIR}/nginx-cross_patch ${B}/bundle/nginx-${NGINX_VERSION}/nginx-cross.patch
    cp ${WORKDIR}/configure-libxslt-conf_patch ${B}/bundle/nginx-${NGINX_VERSION}/configure-libxslt-conf.patch
    cp ${WORKDIR}/Allow-the-overriding-of-the-endianness-via-the-confi_patch ${B}/bundle/nginx-${NGINX_VERSION}/Allow-the-overriding-of-the-endianness-via-the-confi.patch

    cd bundle/nginx-${NGINX_VERSION}
    patch -p1 < nginx-cross.patch
    patch -p1 < configure-libxslt-conf.patch
    patch -p1 < Allow-the-overriding-of-the-endianness-via-the-confi.patch
    cd -
}

# taken from: meta-openembedded/meta-webserver/recipes-httpd/nginx/nginx.inc
do_configure () {
    if [ "${SITEINFO_BITS}" = "64" ]; then
        PTRSIZE=8
    else
        PTRSIZE=4
    fi

    echo $CFLAGS
    echo $LDFLAGS

    # Add the LDFLAGS to the main nginx link to avoid issues with missing GNU_HASH
    echo "MAIN_LINK=\"\${MAIN_LINK} ${LDFLAGS}\"" >> ${B}/bundle/nginx-${NGINX_VERSION}/auto/cc/conf

    ./configure \
    --crossbuild=Linux:${TUNE_ARCH} \
    --with-endian=${@oe.utils.conditional('SITEINFO_ENDIANNESS', 'le', 'little', 'big', d)} \
    --with-int=4 \
    --with-long=${PTRSIZE} \
    --with-long-long=8 \
    --with-ptr-size=${PTRSIZE} \
    --with-sig-atomic-t=${PTRSIZE} \
    --with-size-t=${PTRSIZE} \
    --with-off-t=8 \
    --with-time-t=${PTRSIZE} \
    --with-sys-nerr=132 \
    --prefix=${prefix} \
    ${EXTRA_OECONF} ${PACKAGECONFIG_CONFARGS}

# As stated before, he above configs are intended to support the propper cross-compilation of nginx itself.
# We ommit the below listed config options (from: meta-openembedded/meta-webserver/recipes-httpd/nginx/nginx.inc)
# and use openresties defaults instead:
#    --with-threads \
#    --with-http_gzip_static_module \
#    --conf-path=${sysconfdir}/nginx/nginx.conf \
#    --http-log-path=${localstatedir}/log/nginx/access.log \
#    --error-log-path=${localstatedir}/log/nginx/error.log \
#    --http-client-body-temp-path=/run/nginx/client_body_temp \
#    --http-proxy-temp-path=/run/nginx/proxy_temp \
#    --http-fastcgi-temp-path=/run/nginx/fastcgi_temp \
#    --http-uwsgi-temp-path=/run/nginx/uwsgi_temp \
#    --http-scgi-temp-path=/run/nginx/scgi_temp \
#    --pid-path=/run/nginx/nginx.pid
}

do_compile() {
    # OpenResty uses the standard OpenResty build system
    oe_runmake
}

do_install() {
    oe_runmake 'DESTDIR=${D}' install
}

# package only thing we really need on embedded device
FILES:${PN} = "${bindir}/openresty"
FILES:${PN} += "${bindir}/resty"
FILES:${PN} += "/usr/nginx/sbin/nginx"
FILES:${PN} += "/usr/nginx/html/*"
FILES:${PN} += "/usr/nginx/conf/*"

FILES:${PN} += "/usr/lualib/*"
FILES:${PN} += "/usr/luajit/lib/*.so"
FILES:${PN} += "/usr/luajit/lib/*.so.*"

FILES:${PN}-dev += "/usr/pod/*"
FILES:${PN}-dev += "${bindir}/md2pod.pl"
FILES:${PN}-dev += "${bindir}/nginx-xml2pod"
FILES:${PN}-dev += "${bindir}/opm"
FILES:${PN}-dev += "${bindir}/restydoc*"

# ignore QA errors
INSANE_SKIP:${PN} = "installed-vs-shipped"
INSANE_SKIP:${PN} += "dev-so"
INSANE_SKIP:${PN} += "ldflags"

BBCLASSEXTEND = "native nativesdk"



####################################################################################################
# [openresty]./configure --help
#  --help                             this message
#
#  --prefix=PATH                      set the installation prefix (default to /usr/local/openresty)
#
#  --with-debug                       enable debug logging
#
#  --with-no-pool-patch               enable the no-pool patch for debugging memory issues
#
#  -jN                                pass -jN option to make while building LuaJIT 2.1
#
#  --without-http_echo_module         disable ngx_http_echo_module
#  --without-http_xss_module          disable ngx_http_xss_module
#  --without-http_coolkit_module      disable ngx_http_coolkit_module
#  --without-http_set_misc_module     disable ngx_http_set_misc_module
#  --without-http_form_input_module   disable ngx_http_form_input_module
#  --without-http_encrypted_session_module
#                                     disable ngx_http_encrypted_session_module
#  --without-http_srcache_module      disable ngx_http_srcache_module
#  --without-http_lua_module          disable ngx_http_lua_module
#  --without-http_lua_upstream_module disable ngx_http_lua_upstream_module
#  --without-http_headers_more_module disable ngx_http_headers_more_module
#  --without-http_array_var_module    disable ngx_http_array_var_module
#  --without-http_memc_module         disable ngx_http_memc_module
#  --without-http_redis2_module       disable ngx_http_redis2_module
#  --without-http_redis_module        disable ngx_http_redis_module
#  --without-http_rds_json_module     disable ngx_http_rds_json_module
#  --without-http_rds_csv_module      disable ngx_http_rds_csv_module
#  --without-stream_lua_module        disable ngx_stream_lua_module
#  --without-ngx_devel_kit_module     disable ngx_devel_kit_module
#  --without-stream                   disable TCP/UDP proxy module
#  --without-http_ssl_module          disable ngx_http_ssl_module
#  --without-stream_ssl_module        disable ngx_stream_ssl_module
#
#  --with-http_iconv_module           enable ngx_http_iconv_module
#  --with-http_drizzle_module         enable ngx_http_drizzle_module
#  --with-http_postgres_module        enable ngx_http_postgres_module
#
#  --without-lua_cjson                disable the lua-cjson library
#  --without-lua_tablepool            disable the lua-tablepool library (and by consequence, the
#                                     lua-resty-shell library)
#  --without-lua_redis_parser         disable the lua-redis-parser library
#  --without-lua_rds_parser           disable the lua-rds-parser library
#  --without-lua_resty_dns            disable the lua-resty-dns library
#  --without-lua_resty_memcached      disable the lua-resty-memcached library
#  --without-lua_resty_redis          disable the lua-resty-redis library
#  --without-lua_resty_mysql          disable the lua-resty-mysql library
#  --without-lua_resty_upload         disable the lua-resty-upload library
#  --without-lua_resty_upstream_healthcheck
#                                     disable the lua-resty-upstream-healthcheck library
#  --without-lua_resty_string         disable the lua-resty-string library
#  --without-lua_resty_websocket      disable the lua-resty-websocket library
#  --without-lua_resty_limit_traffic  disable the lua-resty-limit-traffic library
#  --without-lua_resty_lock           disable the lua-resty-lock library
#  --without-lua_resty_lrucache       disable the lua-resty-lrucache library
#  --without-lua_resty_signal         disable the lua-resty-signal library (and by consequence,
#                                     the lua-resty-shell library)
#  --without-lua_resty_shell          disable the lua-resty-shell library
#  --without-lua_resty_core           disable the lua-resty-core library
#
#  --with-luajit=DIR                  use the external LuaJIT 2.1 installation specified by DIR
#  --with-luajit-xcflags=FLAGS        Specify extra C compiler flags for LuaJIT 2.1
#  --with-luajit-ldflags=FLAGS        Specify extra C linker flags for LuaJIT 2.1
#  --without-luajit-lua52             Turns off the LuaJIT extensions from Lua 5.2 that may break
#                                     backward compatibility
#  --without-luajit-gc64              Turns off the LuaJIT GC64 mode (which is enabled by default
#                                     on x86_64)
#
#  --with-libdrizzle=DIR              specify the libdrizzle 1.0 (or drizzle) installation prefix
#  --with-libpq=DIR                   specify the libpq (or postgresql) installation prefix
#  --with-pg_config=PATH              specify the path of the pg_config utility
#
#Options directly inherited from nginx
#
#  --sbin-path=PATH                   set nginx binary pathname
#  --modules-path=PATH                set modules path
#  --conf-path=PATH                   set nginx.conf pathname
#  --error-log-path=PATH              set error log pathname
#  --pid-path=PATH                    set nginx.pid pathname
#  --lock-path=PATH                   set nginx.lock pathname
#
#  --user=USER                        set non-privileged user for
#                                     worker processes
#  --group=GROUP                      set non-privileged group for
#                                     worker processes
#
#  --build=NAME                       set build name
#  --builddir=DIR                     set build directory
#
#  --with-select_module               enable select module
#  --without-select_module            disable select module
#  --with-poll_module                 enable poll module
#  --without-poll_module              disable poll module
#
#  --with-threads                     enable thread pool support
#
#  --with-file-aio                    enable file AIO support
#
#  --with-http_ssl_module             enable ngx_http_ssl_module (default on)
#  --with-http_v2_module              enable ngx_http_v2_module
#  --with-http_v3_module              enable ngx_http_v3_module
#  --with-http_realip_module          enable ngx_http_realip_module
#  --with-http_addition_module        enable ngx_http_addition_module
#  --with-http_xslt_module            enable ngx_http_xslt_module
#  --with-http_xslt_module=dynamic    enable dynamic ngx_http_xslt_module
#  --with-http_image_filter_module    enable ngx_http_image_filter_module
#  --with-http_image_filter_module=dynamic
#                                     enable dynamic ngx_http_image_filter_module
#  --with-http_geoip_module           enable ngx_http_geoip_module
#  --with-http_geoip_module=dynamic   enable dynamic ngx_http_geoip_module
#  --with-http_sub_module             enable ngx_http_sub_module
#  --with-http_dav_module             enable ngx_http_dav_module
#  --with-http_flv_module             enable ngx_http_flv_module
#  --with-http_mp4_module             enable ngx_http_mp4_module
#  --with-http_gunzip_module          enable ngx_http_gunzip_module
#  --with-http_gzip_static_module     enable ngx_http_gzip_static_module
#  --with-http_auth_request_module    enable ngx_http_auth_request_module
#  --with-http_random_index_module    enable ngx_http_random_index_module
#  --with-http_secure_link_module     enable ngx_http_secure_link_module
#  --with-http_degradation_module     enable ngx_http_degradation_module
#  --with-http_slice_module           enable ngx_http_slice_module
#  --with-http_stub_status_module     enable ngx_http_stub_status_module
#
#  --without-http_charset_module      disable ngx_http_charset_module
#  --without-http_gzip_module         disable ngx_http_gzip_module
#  --without-http_ssi_module          disable ngx_http_ssi_module
#  --without-http_userid_module       disable ngx_http_userid_module
#  --without-http_access_module       disable ngx_http_access_module
#  --without-http_auth_basic_module   disable ngx_http_auth_basic_module
#  --without-http_mirror_module       disable ngx_http_mirror_module
#  --without-http_autoindex_module    disable ngx_http_autoindex_module
#  --without-http_geo_module          disable ngx_http_geo_module
#  --without-http_map_module          disable ngx_http_map_module
#  --without-http_split_clients_module disable ngx_http_split_clients_module
#  --without-http_referer_module      disable ngx_http_referer_module
#  --without-http_rewrite_module      disable ngx_http_rewrite_module
#  --without-http_proxy_module        disable ngx_http_proxy_module
#  --without-http_fastcgi_module      disable ngx_http_fastcgi_module
#  --without-http_uwsgi_module        disable ngx_http_uwsgi_module
#  --without-http_scgi_module         disable ngx_http_scgi_module
#  --without-http_grpc_module         disable ngx_http_grpc_module
#  --without-http_memcached_module    disable ngx_http_memcached_module
#  --without-http_limit_conn_module   disable ngx_http_limit_conn_module
#  --without-http_limit_req_module    disable ngx_http_limit_req_module
#  --without-http_empty_gif_module    disable ngx_http_empty_gif_module
#  --without-http_browser_module      disable ngx_http_browser_module
#  --without-http_upstream_hash_module
#                                     disable ngx_http_upstream_hash_module
#  --without-http_upstream_ip_hash_module
#                                     disable ngx_http_upstream_ip_hash_module
#  --without-http_upstream_least_conn_module
#                                     disable ngx_http_upstream_least_conn_module
#  --without-http_upstream_random_module
#                                     disable ngx_http_upstream_random_module
#  --without-http_upstream_keepalive_module
#                                     disable ngx_http_upstream_keepalive_module
#  --without-http_upstream_zone_module
#                                     disable ngx_http_upstream_zone_module
#
#  --with-http_perl_module            enable ngx_http_perl_module
#  --with-http_perl_module=dynamic    enable dynamic ngx_http_perl_module
#  --with-perl_modules_path=PATH      set Perl modules path
#  --with-perl=PATH                   set perl binary pathname
#
#  --http-log-path=PATH               set http access log pathname
#  --http-client-body-temp-path=PATH  set path to store
#                                     http client request body temporary files
#  --http-proxy-temp-path=PATH        set path to store
#                                     http proxy temporary files
#  --http-fastcgi-temp-path=PATH      set path to store
#                                     http fastcgi temporary files
#  --http-uwsgi-temp-path=PATH        set path to store
#                                     http uwsgi temporary files
#  --http-scgi-temp-path=PATH         set path to store
#                                     http scgi temporary files
#
#  --without-http                     disable HTTP server
#  --without-http-cache               disable HTTP cache
#
#  --with-mail                        enable POP3/IMAP4/SMTP proxy module
#  --with-mail=dynamic                enable dynamic POP3/IMAP4/SMTP proxy module
#  --with-mail_ssl_module             enable ngx_mail_ssl_module
#  --without-mail_pop3_module         disable ngx_mail_pop3_module
#  --without-mail_imap_module         disable ngx_mail_imap_module
#  --without-mail_smtp_module         disable ngx_mail_smtp_module
#
#  --with-stream                      enable TCP/UDP proxy module (default on)
#  --with-stream=dynamic              enable dynamic TCP/UDP proxy module
#  --with-stream_ssl_module           enable ngx_stream_ssl_module (default on)
#  --with-stream_realip_module        enable ngx_stream_realip_module
#  --with-stream_geoip_module         enable ngx_stream_geoip_module
#  --with-stream_geoip_module=dynamic enable dynamic ngx_stream_geoip_module
#  --with-stream_ssl_preread_module   enable ngx_stream_ssl_preread_module
#  --without-stream_limit_conn_module disable ngx_stream_limit_conn_module
#  --without-stream_access_module     disable ngx_stream_access_module
#  --without-stream_geo_module        disable ngx_stream_geo_module
#  --without-stream_map_module        disable ngx_stream_map_module
#  --without-stream_split_clients_module
#                                     disable ngx_stream_split_clients_module
#  --without-stream_return_module     disable ngx_stream_return_module
#  --without-stream_upstream_hash_module
#                                     disable ngx_stream_upstream_hash_module
#  --without-stream_upstream_least_conn_module
#                                     disable ngx_stream_upstream_least_conn_module
#  --without-stream_upstream_random_module
#                                     disable ngx_stream_upstream_random_module
#  --without-stream_upstream_zone_module
#                                     disable ngx_stream_upstream_zone_module
#
#  --with-google_perftools_module     enable ngx_google_perftools_module
#  --with-cpp_test_module             enable ngx_cpp_test_module
#
#  --add-module=PATH                  enable external module
#  --add-dynamic-module=PATH          enable dynamic external module
#
#  --with-compat                      dynamic modules compatibility
#
#  --with-cc=PATH                     set C compiler pathname
#  --with-cpp=PATH                    set C preprocessor pathname
#  --with-cc-opt=OPTIONS              set additional C compiler options
#  --with-ld-opt=OPTIONS              set additional linker options
#  --with-cpu-opt=CPU                 build for the specified CPU, valid values:
#                                     pentium, pentiumpro, pentium3, pentium4,
#                                     athlon, opteron, sparc32, sparc64, ppc64
#
#  --without-pcre                     disable PCRE library usage
#  --with-pcre                        force PCRE library usage
#  --with-pcre=DIR                    set path to PCRE library sources
#  --with-pcre-opt=OPTIONS            set additional build options for PCRE
#  --with-pcre-jit                    build PCRE with JIT compilation support
#  --without-pcre2                    do not use PCRE2 library
#
#  --with-zlib=DIR                    set path to zlib library sources
#  --with-zlib-opt=OPTIONS            set additional build options for zlib
#  --with-zlib-asm=CPU                use zlib assembler sources optimized
#                                     for the specified CPU, valid values:
#                                     pentium, pentiumpro
#
#  --with-libatomic                   force libatomic_ops library usage
#  --with-libatomic=DIR               set path to libatomic_ops library sources
#
#  --with-openssl=DIR                 set path to OpenSSL library sources
#  --with-openssl-opt=OPTIONS         set additional build options for OpenSSL
#
#  --dry-run                          dry running the configure, for testing only
#  --platform=PLATFORM                forcibly specify a platform name, for testing only