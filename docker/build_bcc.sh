cd ${BCC_BUILD} && \
    cmake ${BCC_SRC} \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DPYTHON_CMD=python3 \
      -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    make install && \
    rm -rf ${BCC_BUILD}/*