set(VERSION 1.27)

vcpkg_download_distfile(ARCHIVE
    URLS "https://github.com/OpenSC/pkcs11-helper/releases/download/pkcs11-helper-${VERSION}/pkcs11-helper-${VERSION}.0.tar.bz2"
    FILENAME "pkcs11-helper-${VERSION}.tar.bz2"
    SHA512 5799342cb755dae8b7ba0880d652e9d4b4f1e52a74043015e1185e1e059326cb2689bb51957db98060ac2257dee34e2f047dcf3d52ad59fd49b91fedcfc5332b
)

vcpkg_extract_source_archive_ex(
    OUT_SOURCE_PATH SOURCE_PATH
    ARCHIVE ${ARCHIVE}
    REF ${VERSION}
    PATCHES
        0001-nmake-openssl-1.1.1-support.patch
        pkcs11-helper-001-RFC7512.patch
)

vcpkg_build_nmake(
    SOURCE_PATH ${SOURCE_PATH}
    NO_DEBUG
    PROJECT_SUBPATH lib
    PROJECT_NAME Makefile.w32-vc
    OPTIONS
        OPENSSL=1
        OPENSSL_HOME=${CURRENT_PACKAGES_DIR}/../openssl_${TARGET_TRIPLET}
)

file(INSTALL ${SOURCE_PATH}/include/pkcs11-helper-1.0 DESTINATION ${CURRENT_PACKAGES_DIR}/include/)
file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}/lib/pkcs11-helper.dll.lib DESTINATION ${CURRENT_PACKAGES_DIR}/lib)
file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}/lib/pkcs11-helper.dll.lib DESTINATION ${CURRENT_PACKAGES_DIR}/debug/lib)

file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}/lib/libpkcs11-helper-1.dll DESTINATION ${CURRENT_PACKAGES_DIR}/bin)
file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}/lib/libpkcs11-helper-1.dll DESTINATION ${CURRENT_PACKAGES_DIR}/debug/bin)

file(INSTALL ${SOURCE_PATH}/COPYING DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)
