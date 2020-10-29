import functools
import invoke
import json
import re
import unittest
import uuid
from enum import Enum
from io import StringIO
from uuid import uuid4

from inline_scan import InlineScan
from mockserver import MockServer

CONFIG_FILE = 'config_values.json'

run_command = functools.partial(invoke.run, hide=True)


class AccessType(Enum):
    GRANTED = 1
    DENIED = 2


def create_local_image(image_name=None):
    id_ = uuid.uuid4()
    if not image_name:
        image_name = "local-scanning-image-test:{}".format(id_)
    command = "docker build --tag {} -".format(image_name)
    run_command(command, in_stream=StringIO(("FROM busybox\nRUN echo '{}'").format(id_)))
    return image_name


class InlineScanShellScript(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.config = cls._load_config(CONFIG_FILE)

        image_repo = cls.config['image']['repo']
        image_tag = cls.config['image']['tag']

        cls.server = MockServer()
        cls.server.start()

        cls.local_image_name_with_tag = create_local_image()

        cls.inline_scan = InlineScan(
            "http://localhost:{}".format(cls.server.port),
            "faketoken", image_repo, image_tag)

    @staticmethod
    def _load_config(config_file):
        return json.load(open(config_file))

    def test_scan_image_from_public_registry_pass(self):
        self.server.init_test(report_result="pass")
        image_name_with_tag = "docker.io/alpine:3.10.3"
        process_result = self.inline_scan(image_name_with_tag)
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)
        self.assertNotIn(f"docker.io/{image_name_with_tag}", process_result.stdout)

    def test_scan_image_from_public_registry_adds_docker_io_if_omitted(self):
        self.server.init_test(report_result="pass")
        image_name = "alpine:3.9.2"
        image_name_with_registry = f"docker.io/{image_name}"
        process_result = self.inline_scan(image_name)
        scan_result = self.check_output(process_result.stdout, image_name_with_registry)
        self.check_scan_result(scan_result, process_result.return_code)

    def test_scan_image_from_public_registry_fail(self):
        self.server.init_test(report_result="fail")
        image_name_with_tag = "docker.io/alpine:3.9.4"
        process_result = self.inline_scan(image_name_with_tag)
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)

    def test_scan_image_json_output_pass(self):
        self.server.init_test(report_result="pass")
        image_name_with_tag = "docker.io/alpine:3.10.3"
        process_result = self.inline_scan(image_name_with_tag, other_params=["--format", "JSON"])
        out_json = json.loads(process_result.stdout)
        self.assertEqual("pass", out_json['status'])

    def test_scan_image_json_output_fail(self):
        self.server.init_test(report_result="fail")
        image_name_with_tag = "docker.io/alpine:3.9.4"
        process_result = self.inline_scan(image_name_with_tag, other_params=["--format", "JSON"])
        out_json = json.loads(process_result.stdout)
        self.assertEqual("fail", out_json['status'])

    def test_scan_docker_archive(self):
        self.server.init_test(report_result="pass")
        image_name_with_tag = "busybox:latest"
        run_command(f'docker pull {image_name_with_tag}')
        run_command(f'docker save {image_name_with_tag} > image.tar')
        process_result = self.inline_scan(image_name_with_tag, docker_params=["-v", "$(pwd)/image.tar:/tmp/testimage.tar"], other_params=["--storage-type", "docker-archive", "--storage-path", "/tmp/testimage.tar"])
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)

    def test_scan_image_from_public_registry_with_no_tag(self):
        self.server.init_test(report_result="pass")
        image_name = "docker.io/busybox"
        image_name_with_tag = "{}:latest".format(image_name)
        process_result = self.inline_scan(image_name)
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)

    def test_scan_image_by_digest(self):
        self.server.init_test(report_result="pass")
        image_name = "docker.io/python@sha256:c5623df482648cacece4f9652a0ae04b51576c93773ccd43ad459e2a195906dd"  # noqa: E501
        process_result = self.inline_scan(image_name)
        scan_result = self.check_output(
            process_result.stdout,
            "sha256:c5623df482648cacece4f9652a0ae04b51576c93773ccd43ad459e2a195906dd",
        )
        self.check_scan_result(scan_result, process_result.return_code)

    @unittest.skip("not implemented")
    def test_scan_image_from_private_registry(self):
        raise NotImplementedError()

    def test_scan_local_image(self):
        self.server.init_test(report_result="pass")
        process_result = self.inline_scan(self.local_image_name_with_tag, docker_params=["-v", "/var/run/docker.sock:/var/run/docker.sock"], other_params=["--storage-type", "docker-daemon"])
        image_name_with_tag = "localbuild/{}".format(self.local_image_name_with_tag)
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)

    def test_scan_with_clean_flag_pass_image(self):
        self.server.init_test(report_result="pass")
        image_name = "local-scanning-image-test:success"
        command = "docker build --tag {} -".format(image_name)
        run_command(command, in_stream=StringIO("FROM busybox\nRUN echo 'local scanning test'"))

        process_result = self.inline_scan(image_name, clean_flag=True, docker_params=["-v", "/var/run/docker.sock:/var/run/docker.sock"], other_params=["--storage-type", "docker-daemon"])
        self.assertEqual(process_result.return_code, 0)
        for msg in ["Cleaning image from Anchore", "View the full result @"]:
            if msg in process_result.stdout:
                self.fail(
                    f'Expected "{msg}" not to be in output.\nOutput:\n{process_result.stdout}'
                )

    def test_scan_with_clean_flag_fail_image(self):
        self.server.init_test(report_result="fail")
        image_name = "local-scanning-image-test:fail"
        command = "docker build --tag {} -".format(image_name)
        run_command(command, in_stream=StringIO("FROM busybox\nRUN echo 'local scanning test'"))

        process_result = self.inline_scan(image_name, clean_flag=True, docker_params=["-v", "/var/run/docker.sock:/var/run/docker.sock"], other_params=["--storage-type", "docker-daemon"])

        self.assertEqual(process_result.return_code, 1)
        self.assertIn("Cleaning image from Anchore", process_result.stdout)
        self.assertNotIn("View the full result @", process_result.stdout)

    def test_scan_use_image_digest_if_found_in_inspect(self):
        self.server.init_test(report_result="pass")
        image_name = "busybox:latest"
        run_command(f'docker pull {image_name}')
        cmd_result = run_command(f'docker inspect {image_name}')
        cmd_out_json = json.loads(cmd_result.stdout)
        digests = [digest.split("@sha256:")[-1] for digest in cmd_out_json[0]['RepoDigests']]

        process_result = self.inline_scan(image_name)

        assert any(s in process_result.stdout for s in digests)

    @unittest.skip("need to review, as the digest calculation has changed")
    def test_scan_generate_and_use_digest_for_local_built_image(self):
        self.server.init_test(report_result="pass")
        random_id = str(uuid4())
        image_name = f"test-{random_id}:another"
        build_command = "docker build --tag {} -".format(image_name)
        run_command(
            build_command,
            in_stream=StringIO("FROM busybox\nRUN echo 'local scanning test'"),
        )

        inspect_command = f'docker inspect {image_name} | shasum -a 256'
        generated_digest = run_command(inspect_command).stdout.strip('\n\t -')

        process_result = self.inline_scan(image_name, docker_params=["-v", "/var/run/docker.sock:/var/run/docker.sock"], other_params=["--storage-type", "docker-daemon"])

        if generated_digest not in process_result.stdout:
            self.fail(
                f'Expected "{generated_digest}" to be in output:\n"{process_result.stdout}"',
            )

    def test_scan_should_skip_analyse_if_has_already_been_scanned(self):
        self.server.init_test(report_result="pass")
        image_name_with_tag = "docker.io/alpine:3.9.5"
        process_result = self.inline_scan(image_name_with_tag)
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)

        # The result should now be found by the script and skip the analysis
        process_result_again = self.inline_scan(image_name_with_tag)
        self.assertIn(
            "Image digest found on Sysdig Secure, skipping analysis.",
            process_result_again.stdout,
        )
        self.assertNotIn(
            "Converting image",
            process_result_again.stdout,
        )

    def test_scan_without_tag_should_take_latest_even_with_multiple_tags_in_local_registry(self):
        """
            This tests verifies that without speficying tags the script uses latest
            even if there are more than one tags in the local registry.

            This also ensure that docker save is invoked correctly: in fact
            docker save potentially (if not invoked with 'repo/image:tag') creates tarfiles
            with more than one image. This breaks Anchore/Skopeo analysis.
        """
        self.server.init_test(report_result="pass")
        for image in ["alpine:latest", "alpine:3.9.6"]:
            run_command(f'docker pull {image}')

        image_name_with_tag = "alpine:latest"
        process_result = self.inline_scan("alpine", docker_params=["-v", "/var/run/docker.sock:/var/run/docker.sock"], other_params=["--storage-type", "docker-daemon"])
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)

    def test_scan_non_existing_image(self):
        process_result = self.inline_scan("non_existing_image", docker_params=["-v", "/var/run/docker.sock:/var/run/docker.sock"], other_params=["--storage-type", "docker-daemon"])
        self.assertEqual(process_result.return_code, 3)
        self.assertIn("Please pull remote image", process_result.stderr)
        self.assertIn("Failed to retrieve the image", process_result.stderr)

        process_result = self.inline_scan("non_existing_image")
        self.assertIn("Please pull remote image", process_result.stderr)
        self.assertIn("Failed to retrieve the image", process_result.stderr)

    def test_scan_with_no_auth_token(self):
        process_result = self.inline_scan("alpine:latest", omit_token=True, docker_params=["-v", "/var/run/docker.sock:/var/run/docker.sock"], other_params=["--storage-type", "docker-daemon"])
        self.assertEqual(process_result.return_code, 2)
        self.assertIn("ERROR: must provide the Sysdig Secure API token", process_result.stderr)

    def test_scan_with_http500_get_scan_result_api(self):
        self.server.init_test(report_result="pass", return_error_500=2)
        image_name_with_tag = "docker.io/alpine:3.10.3"
        process_result = self.inline_scan(image_name_with_tag)
        scan_result = self.check_output(process_result.stdout, image_name_with_tag)
        self.check_scan_result(scan_result, process_result.return_code)
        self.assertNotIn(f"docker.io/{image_name_with_tag}", process_result.stdout)

    @staticmethod
    def find_message_index_in_output(message, output_lines):
        for index, line in enumerate(output_lines):
            if message in line:
                return index
        return None

    def check_output(self, stdout, image_name_with_tag):
        expected_messages = [
            "Analysis complete!",
            "Sending analysis result to"]

        remaining_output_lines = stdout.splitlines()
        for message in expected_messages:
            message_index = self.find_message_index_in_output(message, remaining_output_lines)
            if message_index is None:
                self.fail("'{}' not found in output".format(message))
            else:
                remaining_output_lines = remaining_output_lines[message_index:]

        match = re.search(r'Status:\s*(?P<result>\w*)', stdout)
        self.assertIsNotNone(match)
        scan_result = match.group('result')

        re.search(r"Status is (?P<result>\w*)\n", stdout)
        self.assertIsNotNone(match)
        self.assertEqual(scan_result, match.group('result'))

        self.assertIn(image_name_with_tag, stdout)

        return scan_result

    def check_scan_result(self, scan_result, return_code):
        if scan_result == "fail":
            self.assertEqual(return_code, 1)
        elif scan_result == "pass":
            self.assertEqual(return_code, 0)
        else:
            self.fail("Unexpected scan result: %s" % scan_result)

    @classmethod
    def tearDownClass(cls):
        run_command("docker rmi {}".format(cls.local_image_name_with_tag))
        cls.server.shutdown_server()
