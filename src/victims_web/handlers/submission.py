from json import loads
from os.path import isfile
from subprocess import check_output, CalledProcessError

from victims_web import config
from victims_web.handlers.task import task
from victims_web.model.evd import StagedSubmission


@task
def hash_submission(submission_id):
    """
    Helper method to process an archive at source where possible from a
    submission.
    """
    submission = StagedSubmission.objects(id=submission_id).first()

    if not submission:
        config.LOGGER.debug('Submission %s not found.' % (submission_id))
        return

    if not submission.fingerprint.empty:
        submission.comment('Entry alread exits. Skipping hashing.')
        return

    if not isfile(submission.source):
        submission.comment('Source file not found.')
        return

    if submission.group not in config.HASHING_COMMANDS:
        submission.comment('Hashing command for this group not found.')
        return

    command = config.HASHING_COMMANDS[submission.group].format(
        archive=submission.source)
    try:
        output = check_output(command, shell=True).strip()
        count = 0
        for line in output.split('\n'):
            json_data = loads(line)

            # make sure metadata is a list
            meta = json_data.get('metadata', [])
            if isinstance(meta, dict):
                meta = [meta]
            print(meta)
            # old style
            submission.metadata = meta
            submission.fingerprint.files = \
                json_data['hashes']['sha512']['files']

            if count > 0:
                # create a new submission for each embedded entry
                s = submission.copy()
                s.id = None
            else:
                s = submission

            s.approval = 'PENDING_APPROVAL'
            s.comment('Auto hash entry added')
            s.save()
            count += 1
    except CalledProcessError as e:
        submission.comment(e)
        config.LOGGER.debug('Command execution failed for "%s"' % (command))
    except Exception as e:
        submission.comment(e)
        config.LOGGER.warn('Failed to hash: ' + e.message)


def set_hash(submission):
    if isinstance(submission, basestring):
        sid = str(submission)
    else:
        sid = str(submission.id)
    hash_submission(sid)
