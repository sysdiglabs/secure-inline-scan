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

    def __call__(self, image, url=None, token=None, clean_flag=False, 
            omit_token=False, docker_params=[], other_params=[]):
        if not url:
            if platform.system() == 'Darwin':
                # Hack for docker in Mac
                url = self.url.replace("localhost", "docker.for.mac.host.internal")
            else:
                url = self.url
        if not token:
            token = self.token

        cmdline = ["docker", "run", "--rm", "--network", "host"]

        cmdline += docker_params

        cmdline.append("{}:{}".format(
            self.image_repo,
            self.image_tag))

        cmdline += ["-s", url]

        if not omit_token:
            cmdline.append('-k')
            cmdline.append(token)

        if clean_flag:
            cmdline.append('-c')

        cmdline += other_params

        cmdline.append(image)

        return invoke.run(" ".join(cmdline), hide=False, warn=True, echo=True)
