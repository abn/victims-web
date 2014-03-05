#!/usr/bin/env bash

PYTHON_CMD="python"

${PYTHON_CMD} -c \
    "from flask.ext.script import Manager; \
    from victims_web.application import app; \
    Manager(app).run()" \
    shell
