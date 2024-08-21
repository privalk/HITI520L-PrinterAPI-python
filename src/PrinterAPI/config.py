import json


class Config:

    def load_config(self):
        with open('src\PrinterAPI\config.json', 'r') as config_file:
            config = json.load(config_file)
        return config
    
    def __init__(self):
        self.config = self.load_config()

    
cfg=Config().config

   