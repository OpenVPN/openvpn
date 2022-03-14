set(VERSION 1.28.0)

vcpkg_download_distfile(ARCHIVE
    URLS "https://github.com/OpenSC/pkcs11-helper/releases/download/pkcs11-helper-${VERSION}/pkcs11-helper-${VERSION}.tar.gz"
    FILENAME "pkcs11-helper-${VERSION}.tar.gz"
    SHA512 1c1cc7f83ed360fabdcfa68d0eafa7d25be03e68c6a202e7ad2907feb472663bb34e12b9e162344ec221a4298abc02acdc75f0f45d9a89657aa7ac55e59badd5
)

vcpkg_extract_source_archive_ex(
    OUT_SOURCE_PATH SOURCE_PATH
    ARCHIVE ${ARCHIVE}
    REF ${VERSION}
    PATCHES
        0001-nmake-compatibility-with-vcpkg-nmake.patch
        0002-pkcs11.h-rename-interface-parameter.patch
        0003-config-w32-vc.h.in-indicate-OpenSSL-EC-support.patch
        pkcs11-helper-001-RFC7512.patch
)

vcpkg_build_nmake(
    SOURCE_PATH ${SOURCE_PATH}
    PROJECT_SUBPATH lib
    PROJECT_NAME Makefile.w32-vc
    OPTIONS
        OPENSSL=1
        OPENSSL_HOME=${CURRENT_PACKAGES_DIR}/../openssl_${TARGET_TRIPLET}
)

file(INSTALL ${SOURCE_PATH}/include/pkcs11-helper-1.0 DESTINATION ${CURRENT_PACKAGES_DIR}/include/)
file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel/lib/pkcs11-helper.dll.lib DESTINATION ${CURRENT_PACKAGES_DIR}/lib)
file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg/lib/pkcs11-helper.dll.lib DESTINATION ${CURRENT_PACKAGES_DIR}/debug/lib)

file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel/lib/libpkcs11-helper-1.dll DESTINATION ${CURRENT_PACKAGES_DIR}/bin)
file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg/lib/libpkcs11-helper-1.dll DESTINATION ${CURRENT_PACKAGES_DIR}/debug/bin)

file(INSTALL ${SOURCE_PATH}/COPYING DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)
