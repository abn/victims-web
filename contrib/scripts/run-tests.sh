#! /usr/bin/env bash
# to be run in the dev environment

SCRIPT_DIR=$(dirname $0)

TEST_DIR=$(dirname "$SCRIPT_DIR")
while true; do
	if [ -d "${TEST_DIR}/test" ]; then
		TEST_DIR="${TEST_DIR}/test"
		break;
	elif [ "/" == "${TEST_DIR}" ]; then
		echo "Could not find test dirctory."
		exit 1
	fi
	TEST_DIR=$(dirname "${TEST_DIR}")
done

MONGOSH="$SCRIPT_DIR/mongo-db-ctl.sh"
# gracefully start db
bash "$MONGOSH" start

if [ $? -ne 0 ]; then
	echo "[ERROR] Could not start mongodb-server"
	exit 1
fi

# execute tests
if ! type -p nosetests > /dev/null; then
	echo "[ERROR] nosetests not found. Cannot run tests."
else
	python "$(which nosetests)" --with-coverage --cover-package=victims_web --cover-min-percentage=0 -v ${TEST_DIR}/*.py
fi

# stop db
bash "$MONGOSH" stop

