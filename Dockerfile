FROM scratch

COPY out/* /bin/
ENTRYPOINT ["/bin/installer"]
