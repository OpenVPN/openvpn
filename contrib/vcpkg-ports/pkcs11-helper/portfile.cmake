set(VERSION 1.31.0)

vcpkg_download_distfile(ARCHIVE
    URLS "https://github.com/OpenSC/pkcs11-helper/releases/download/pkcs11-helper-${VERSION}/pkcs11-helper-${VERSION}.tar.bz2"
    FILENAME "pkcs11-helper-${VERSION}.tar.bz2"
    SHA512 0833efc59e9093dd398a54640d858b01a830ef7adfb40321c1e0ed0afa004500fc1259cc66bc49c5263935adeda0a3bfe658de538eefd66888685a71f731c484
)

vcpkg_extract_source_archive_ex(
    OUT_SOURCE_PATH SOURCE_PATH
    ARCHIVE ${ARCHIVE}
    REF ${VERSION}
    PATCHES
        nmake-compatibility-with-vcpkg-nmake.patch
        config-w32-vc.h.in-indicate-OpenSSL.patch
        pkcs11-helper-001-RFC7512.patch
)

if(VCPKG_TARGET_IS_WINDOWS AND NOT VCPKG_TARGET_IS_MINGW)
  vcpkg_build_nmake(
    SOURCE_PATH ${SOURCE_PATH}
    PROJECT_SUBPATH lib
    PROJECT_NAME Makefile.w32-vc
    OPTIONS
        OPENSSL=1
        OPENSSL_HOME=${CURRENT_PACKAGES_DIR}/../openssl_${TARGET_TRIPLET}
  )

  file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel/lib/pkcs11-helper.dll.lib DESTINATION ${CURRENT_PACKAGES_DIR}/lib RENAME pkcs11-helper.lib)
  file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg/lib/pkcs11-helper.dll.lib DESTINATION ${CURRENT_PACKAGES_DIR}/debug/lib RENAME pkcs11-helper.lib)

  file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel/lib/libpkcs11-helper-1.dll DESTINATION ${CURRENT_PACKAGES_DIR}/bin)
  file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg/lib/libpkcs11-helper-1.dll DESTINATION ${CURRENT_PACKAGES_DIR}/debug/bin)

  set(PACKAGE_VERSION "${VERSION}")
    set(libdir [[${prefix}/lib]])
    set(exec_prefix [[${prefix}]])
    set(PKCS11H_FEATURES key_prompt openssl engine_crypto_cryptoapi engine_crypto_openssl debug threading token data certificate slotevent engine_crypto)
    set(LIBS -lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32)
    if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "release")
        set(includedir [[${prefix}/include]])
        set(outfile "${CURRENT_PACKAGES_DIR}/lib/pkgconfig/libpkcs11-helper-1.pc")
        configure_file("${SOURCE_PATH}/lib/libpkcs11-helper-1.pc.in" "${outfile}" @ONLY)
    endif()
    if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "debug")
        set(includedir [[${prefix}/../include]])
        set(outfile "${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig/libpkcs11-helper-1.pc")
        configure_file("${SOURCE_PATH}/lib/libpkcs11-helper-1.pc.in" "${outfile}" @ONLY)
    endif()

  file(INSTALL ${SOURCE_PATH}/include/pkcs11-helper-1.0 DESTINATION ${CURRENT_PACKAGES_DIR}/include/)

else()
  find_program(man_to_html man2html REQUIRED)

  vcpkg_configure_make(
    SOURCE_PATH ${SOURCE_PATH}
    OPTIONS --disable-crypto-engine-gnutls --disable-crypto-engine-nss
    --disable-crypto-engine-polarssl --disable-crypto-engine-mbedtls
    )
  vcpkg_install_make()

  file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")
endif()

vcpkg_fixup_pkgconfig()
vcpkg_copy_pdbs()

file(INSTALL ${SOURCE_PATH}/COPYING DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)
