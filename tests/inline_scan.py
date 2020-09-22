import invoke
import platform

LOGIN_ENDPOINT = '/api/login'
TOKEN_ENDPOINT = '/api/token'
TEAMS_ENDPOINT = "/api/teams/light"
ANCHORE_IMAGES_ENDPOINT = '/api/scanning/v1/anchore/images'


class InlineScan:

    ANCHORE_IMAGE = "docker.io/anchore/anchore-engine:v0.7.3"

    def __init__(self, url, token, image_repo, image_tag):
        self.image_repo = image_repo
        self.image_tag = image_tag
        self.url = url
        self.headers = self._headers()
        self.token = token
        self.headers["Authorization"] = "Bearer {token}".format(token=token)

    def _headers(self):
        return {
            'X-Sysdig-Product': "SDS",
            'content-type': 'application/json',
        }

    def __call__(self, image, url=None, token=None, pull=False,
                 clean_flag=False, volume="", omit_token=False, input_tar=None):
        if not url:
            if platform.system() == 'Darwin':
                # Hack for docker in Mac
                url = self.url.replace("localhost", "docker.for.mac.host.internal")
            else:
                url = self.url
        if not token:
            token = self.token

        cmdline = ["docker", "run", "--rm", "--network", "host"]

        if input_tar:
            cmdline += ["-v", "$(pwd)/image.tar:/tmp/image.tar"]
        elif not pull:
            cmdline += ["-v", "/var/run/docker.sock:/var/run/docker.sock"]

        cmdline.append("{}:{}".format(
            self.image_repo,
            self.image_tag))

        cmdline += ["-s", url]

        if not omit_token:
            cmdline.append('-k')
            cmdline.append(token)

        if volume:
            cmdline.append('-v')
            cmdline.append(volume)
        if clean_flag:
            cmdline.append('-c')

        if pull:
            cmdline.append('-P')
        elif input_tar:
            cmdline.append(input_tar)

        cmdline.append(image)

        return invoke.run(" ".join(cmdline), hide=False, warn=True, echo=True)
