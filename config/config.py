import configparser


class Config:
    def __init__(self) -> None:
        self.config = configparser.ConfigParser()
        self.config.read_file(open('config.ini'))

    def token(self):
        return self.config['REST']['token']

    def api_base(self):
        return self.config['REST']['API_BASE']


