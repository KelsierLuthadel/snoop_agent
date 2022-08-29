import requests as requests

from config.config import Config


class RestInterface:
    def __init__(self) -> None:
        self.entities_api = Config().api_base() + "entities/"
        self.entity_api = Config().api_base() + "entities/{id}/"
        self.headers = {
            'Authorization': 'Token ' + Config().token()
        }

    def get_entities(self, data=None, params=None):
        return requests.request("GET",  self.entities_api,
                                headers=self.headers, data=data, params=params)

    def create_entity(self, data=None, params=None):
        return requests.request("POST",  self.entities_api,
                                headers=self.headers, data=data, params=params)

    def get_entity(self, entity_id, data=None, params=None):
        return requests.request("GET", self.entity_api.format(entity_id),
                                headers=self.headers, data=data, params=params)

    def update_entity(self, entity_id, data=None, params=None):
        return requests.request("PUT", self.entity_api.format(id=entity_id),
                                headers=self.headers, data=data, params=params)

    def delete_entity(self, entity_id):
        return requests.request("DELETE", self.entity_api.format(entity_id),
                                headers=self.headers)
